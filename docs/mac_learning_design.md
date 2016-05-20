# Mac Learning Design Opennsl plugin:
----------------------

- [Design considerations](#design-considerations)
- [High Level Design](#high-level-design)
- [Design detail](#design-detail)
- [Operations on MAC table](#operations-mac-table)
- [References](#references)


## Design considerations:
-------------------------

i. Reliability
   There is no dynamic memory allocation in the opennsl plugin layer. This is required to shorten the time to copy information given by the ASIC so that no entry is missed.
ii. Performance
    The callback function is running in a separate thread. There is a need to separate the data storage for main thread and callback thread so that the main thread can read and the callback thread can write to different buffers at the same time without any waiting period.
iii. Efficiency
     The data structure that is used must have search operation of O(1). This is required because when ASIC learns a MAC address on a port and later it moves to a different port in a relatively short time which makes it part of the same hmap. Hence instead of adding new entry in the hmap, the older entry should be removed.

The hash map used in the opennsl plugin only holds the delta of the recent changes. The final MAC Table is in OVSDB.


## High level design:
---------------------

```
                                                                                               ops-switchd process
  +----------------------------------------------------------------------------------------------------------------+
  |                                          +------------------------------------------------------------------+  |
  |  +-------------+                         |                       opennsl plugin                             |  |
  |  | vswitchd    |                     1   |                                                                  |  |
  |  | main        |-------------------------|--------> init()                                                  |  |
  |  | thread      |                         |            |                                                     |  |
  |  +-------------+                         |            |                                                     |  |
  |        ^                                 |            |                                                     |  |
  |        |                                 |            |                                           2         |  |
  |        |                                 |            |                                        +------      |  |
  |        |                                 |            v                                        |     |      |  |
  |        |                                 |    mac_learning_init +-----> opennsl_l2_addr_reg(cb_fn)   |      |  |
  |        |                                 |                      |-----> opennsl_l2_traverse(cb_fun)  +----  |  |
  |        |                                 |                                                           |   |  |  |
  |        |                                 |                                                           v   |  |  |
  |        |                                 |   +--------------+                                 +--+  +--+ |  |  |
  |        |           3                     |   |              |                                 |  |  |--| |  |  |
  |        +---------------------------------|---|  bcm timer   |                                 |  |  |  | |  |  |
  |        |                                 |   |    thread    |                                 +--+  +--+ |  |  |
  |        |                                 |   +--------------+                                   HMAPS    |  |  |
  |        |           3                     |                                                               |  |  |
  |        +---------------------------------|---------------------------------------------------------------+  |  |
  |                                          |                                                                  |  |
  |                                          +------------------------------------------------------------------+  |
  +----------------------------------------------------------------------------------------------------------------+

```

The above diagram describes the interaction between different functions and threads in ops-switchd process.
1. When the process starts, the main thread creates bcm init thread for the initialization. This initialization includes registering for callback functions in SDK when a L2 address is added/deleted in L2 table.
2. The callback function is called by the SDK in context of a separate thread which adds the entries in the hmap.
3. The notification to switchd main thread is triggered when either the current in use hmap is full or the timer thread times out, which ever event happens first.


## Design detail:
-----------------

1. Asic-plugin changes (ops-switchd, ops-switchd-opennsl-plugin)
   This comprises of the PD implementation of PI-PD API.
2. Registering for bcm callback (ops-switchd-opennsl-plugin)
   MACs are learnt by ASIC and are stored in L2 Table in ASIC.
3. Callback function, updating the hmap (ops-switchd-opennsl-plugin)
4. Notifying switchd main thread (ops-switchd-opennsl-plugin)

### Details:
------------

1. Asic-plugin changes
                                                  switchd main thread
    +-------------------------------------------------------------------------------------------------------+
    |      main() in ovs-vswitchd.c                         |            bcm_plugins.c                      |
    |                                                       |                                               |
    |      plugins_init() ----------------------------------|---------------> init()                        |
    |                                                       |                                               |
    |                                                       |            get_mac_learning_hmap (added)      |
    +-------------------------------------------------------------------------------------------------------+

  Changes involves addition of platform specific function in the ASIC plugin.


2. Registering for bcm callback

    bcm_init thread

    init()   -------------> ops_mac_learning_init()  ------------------> opennsl_l2_addr_register & opennsl_l2_traverse()

   The bcm init thread is created by switchd main thread for the initialization of the ASIC SDK. Initialization for mac learning involves registeration of callback for learnt l2 addresses as well as for traverse the current l2 addresses in L2 MAC table. Currently there is no benefit of registering for opennsl_l2_traverse as whenever switchd process restarts, ASIC is reset. Once HA infrastructure is in place, tiis function will provide a way for mark and sweep when the process restarts in order to avoid resetting the hardware and instead apply only incremental changes to the database.


3. Callback function and updating the hmap

   Whenever any L2 entry is added/deleted in L2 Table in ASIC, the SDK invokes the registered callback function (Point 2.). The main criteria for this callback function is to spend least amount of time because it is not a bulk call.

   The hash is the combination of MAC address, VLAN and hw_unit.

4. How hash maps are getting used?

   The opennsl plugin writes to the hmap and the mac learning plugin reads from the hmaps. As the opennsl plugin and mac learning plugin are part of same ops-switchd process, using of two hmaps avoids using lock for reading the hmap. While writing to hmap, the lock needs to be used as bcm init thread and thread created for SDK callback can simultaneously write to the hmap. Using two hmap buffer also provides advantage in case of burst of the incoming L2 entries that fills up the current hmap completely, leading immediate switch to use of the second hmap to avoid any loss of updates from the SDK.


5. Notifying switchd main thread

   When the updates for L2 entry are received from the SDK, they are stored locally in opennsl plugin. In order for it to be written in OVSDB, the updates need to go to switchd main thread. OVS uses seq_change to trigger notification to the thread waiting for that sequence change event.
   The sequence change can occur in the two cases:
   i. The current hmap is full.
   ii. The timer thread times out and there is at least an entry in the hmap.


## Operations on MAC table:
---------------------------

Currently supported operations:

i. MAC Address (dynamic) learning
   MAC address is learnt dynamically when a frame is received whose source MAC address, VLAN is not present in the MAC table for the port.

ii. MAC Move
    MAC Move occurs when the same MAC address is learnt on a different port in the bridge for same VLAN.

iii. MAC address aging
     Dynamically learnt MAC addresses are deleted from the MAC table if no frame is received for the same MAC address and VLAN on the port by the time age-out timer expires.
     If after the age out time interval (x seconds) the entry is active, the entry is first marked as inactive and after another age out interval, it is removed from the L2 table (2x seconds).

## Current hard coded values:
-----------------------------

1. Two hmap buffers
2. hmap buffer size is 16K (can be changed to optimum value after having scale performance testing).
3. The timeout of the timer thread to invoke notification to switchd main thread is 1 minute.

## References:
--------------

* [Openvswitch] (http://openvswitch.org/)
* (/documents/dev/ops/docs/mac_learning_feature_design)
