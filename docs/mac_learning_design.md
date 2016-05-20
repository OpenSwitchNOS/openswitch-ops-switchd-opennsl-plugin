# Mac Learning Design Opennsl plugin
------------------------------------

- [Design considerations](#design-considerations)
- [High Level Design](#high-level-design)
- [Design detail](#design-detail)
- [Operations on MAC table](#operations-on-mac-table)
- [References](#references)


## Design considerations
------------------------

- Reliability
   There is no dynamic memory allocation in the opennsl plugin layer. This is required to shorten the time to copy information given by the ASIC so that no entry is missed.
- Performance
  The callback function is running in a separate thread. There is a need to separate the data storage for main thread and callback thread so that the main thread can read and the callback thread can write to different buffers at the same time without any contention.
- Efficiency
 The data structure that is used must have search operation of O(1). This is required because when ASIC learns a MAC address on a port and later it moves to a different port in a relatively short time, the entry will be part of the same hmap. Hence, instead of adding a new entry in the hmap, the older entry is removed.

The hash map used in the opennsl plugin only holds the delta of the recent changes. The final MAC Table is in the OVSDB.


## High level design
--------------------

```ditaa
                                                                                       ops-switchd process
  +--------------------------------------------------------------------------------------------------------+
  |                                  +------------------------------------------------------------------+  |
  |  +-------------+                 |                       opennsl plugin                             |  |
  |  | vswitchd    |             1   |                                                                  |  |
  |  | main        |-----------------|--------> init()                                                  |  |
  |  | thread      |                 |            |                                                     |  |
  |  +-------------+                 |            |                                                     |  |
  |        ^                         |            |                                                     |  |
  |        |                         |            |                                           2         |  |
  |        |                         |            |                                        +------      |  |
  |        |                         |            v                                        |     |      |  |
  |        |                         |    mac_learning_init +-----> opennsl_l2_addr_reg(cb_fn)   |      |  |
  |        |                         |                      |-----> opennsl_l2_traverse(cb_fun)  +----  |  |
  |        |                         |                                                           |   |  |  |
  |        |                         |                                                           v   |  |  |
  |        |                         |   +--------------+                                 +--+  +--+ |  |  |
  |        |           3             |   |              |                                 |  |  |--| |  |  |
  |        +-------------------------|---|  bcm timer   |                                 |  |  |  | |  |  |
  |        |                         |   |    thread    |                                 +--+  +--+ |  |  |
  |        |                         |   +--------------+                                   HMAPS    |  |  |
  |        |           3             |                                                               |  |  |
  |        +-------------------------|---------------------------------------------------------------+  |  |
  |                                  |                                                                  |  |
  |                                  +------------------------------------------------------------------+  |
  +--------------------------------------------------------------------------------------------------------+

```

The above diagram describes the interaction between the different functions and threads in the ops-switchd process.
1. When the process starts, the main thread creates `bcm init thread` for the initialization that registers for callback functions in the SDK when a L2 address is added or deleted in the L2 table.
2. When entries are changed in ASIC L2 table, the SDK creates new thread and calls the callback function. The callback function then adds entries in the hmap.
3. The notification to the switchd main thread is triggered when either the current hmap in use is full or the timer thread times out, which ever event happens first.


## Design detail
----------------

The following are the details featured in this design:
- ASIC Plugin changes (ops-switchd, ops-switchd-opennsl-plugin)
   This comprises of the PD implementation of PI-PD API.
- Registering for bcm callback (ops-switchd-opennsl-plugin)
   MACs are learnt by ASIC and are stored in L2 Table in ASIC.
- Callback function, updating the hmap (ops-switchd-opennsl-plugin)
- Use of hmaps
- Notifying switchd main thread (ops-switchd-opennsl-plugin)

### Details
-----------

1. ASIC Plugin changes
```ditaa
                                               switchd main thread
    +----------------------------------------------------------------------------------------------------+
    |      main() in ovs-vswitchd.c                      |            bcm_plugins.c                      |
    |                                                    |                                               |
    |      plugins_init() -------------------------------|---------------> init()                        |
    |                                                    |                                               |
    |                                                    |            get_mac_learning_hmap (added)      |
    +----------------------------------------------------------------------------------------------------+
```
  Changes involves the addition of a platform-specific function in the ASIC plugin.

2. Registering for BCM callback
```ditaa
    bcm_init thread

    init()   --------> ops_mac_learning_init()  --------> opennsl_l2_addr_register & opennsl_l2_traverse()
```

   The bcm init thread is created by the switchd main thread for the initialization of the ASIC SDK. Initialization for mac learning involves registration of callback for learnt L2 addresses as well as initial traverse of current addresses in L2 table. Right now, there is no benefit of registering for `opennsl_l2_traverse` as whenever the ops-switchd process restarts, the ASIC is reset. But once the HA infrastructure is in place, this function will provide a way to mark and sweep entries when the ops-switchd process restarts, thereby avoiding reset of the hardware and instead apply only incremental changes to the database.

3. Callback function and updating the hmap

   Whenever any L2 entry is added or deleted in the ASIC L2 table, the SDK invokes the registered callback function (Point 2.). There can be thousands of entries changed in the L2 table leading to that many calls to callback function (the callback function does not handle bulk entries). Hence, the main criteria for this callback function is to spend the least amount of time.

   The hash is the combination of MAC address, VLAN and hw_unit.

4. Use of hmaps

   The opennsl plugin writes to the hmap and the MAC learning plugin reads from the hmap. Since the opennsl plugin and MAC learning plugin are part of the same process (ops-switchd), using of two hmaps avoids using lock for reading the hmap. While writing to hmap, the lock is needed as bcm init thread and thread created for SDK callback can simultaneously write to the hmap. Using two hmap buffers also provide an advantage in case of burst of the incoming L2 entries that completely fills up the current hmap, leading to immediate switch of the current hmap in use to avoid any loss of updates from the SDK.

5. Notifying the switchd main thread

   When the updates for L2 entry are received from the SDK, they are stored locally in opennsl plugin. In order for it to be written in OVSDB, the updates needs to be received by the switchd main thread. OVS uses seq_change to trigger notification to the thread waiting for that sequence change event.
   The sequence change can occur in the two cases:
   - The current hmap is full.
   - The timer thread times out and there is at least an entry in the hmap.


## Operations on MAC table
--------------------------

Currently supported operations:

- MAC Address (dynamic) learning
   MAC address is learnt dynamically when a frame received has source MAC address, VLAN that is not present in the MAC table for the port.
   [For AS5712, the maximum MAC addresses in L2 table supported is 32k]

- MAC Move
   MAC Move occurs when the same MAC address is learnt on a different port in the bridge for the same VLAN.

- MAC address aging
   Dynamically learnt MAC addresses are deleted from the MAC table if no frame is received for the same MAC address and VLAN on the port by the time age-out timer expires.
   If after the age out time interval (x seconds) the entry is active, the entry is first marked as inactive and after another age out interval, it is removed from the L2 table (2x seconds).

## Current hard coded values
----------------------------

- Two hmap buffers
- The hmap buffer size is 16K (can be changed to an optimum value after having scale performance testing).
- The timeout of the timer thread to invoke notification to the switchd main thread is one (1) minute.

## References
-------------

* [Openvswitch](http://openvswitch.org/)
* [Feature design](/documents/dev/ops/docs/mac_learning_feature_design)
