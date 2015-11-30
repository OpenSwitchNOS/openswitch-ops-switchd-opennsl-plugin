# opennsl plugin test cases

## Contents
  * [opennsl plugin test cases](#opennsl-plugin-test-cases)
    * [Test loopback creation and deletion](#test-loopback-creation-and-deletion)
      * [Objective](#objective)
      * [Requirements](#requirements)
      * [Description](#description)

## Test loopback creation and deletion
### Objective
Verify creating a loopback interface and assigning ip address to it. Also verify deleting the loopback interface.
### Requirements
 - RTL setup with physical switch
### Setup
#### Topology Diagram
```
[switch1] <==> [host1]
```
### Description
1. Create port 1 on switch1
2. Assign ip address 10.0.10.1 to port 1
3. Get the uuid of the port 1
4. Using ovsdb-client command create a loopback interface lo:1 of type loopback, create a port lo:1 and assign the interface lo:1 to it and assign the port lo:1 to vrf_default along with port 1.
5. Assign ip address 2.2.2.1 to this port lo:1
6. Configure host1 eth1 with ip 10.0.10.2 and default gateway 10.0.10.1
7. Ping 2.2.2.1 from host1
8. Using ovsdb-client delete port lo:1
9. Ping 2.2.2.1 from host1
### Test Result Criteria
#### Test Pass Criteria
1st ping should pass and second ping should fail.
#### Test Fail Criteria
1st ping fails and second ping passes.
