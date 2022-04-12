# Sipcollect
collects sip-packets and stores them in mysql
---
sipcollect traces VoIP sip-messages, extracts the Call-ID and stores every individial message in a mysql-table.\
Most Call-Detail-Records (CDR) of Voice Switches include the Call-ID of every Call-Leg.\
By referencing to the mysql-records with that Call-ID you have all relevant signaling messages of that Call.\
Usually, you would then display the sip-messages in a web-application showing the message-flow.

## INSTALLATION
sipcollect builds with cmake, installation requirements are 
- g++
- pkg-config
- cmake
- libpcap
- libmysqlclient

The installation script `install.sh` will take care of the libraries, but g++, pkg-config and cmake need to be there at first.

---
##### 1. run the install script
```sh
sudo ./install.sh
```
---
##### 2. After the successful build you need to set up the mysql-database.
```sql
CREATE DATABASE `sipcollect`;
CREATE TABLE `sipcollect`.`sip` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `callid` varchar(255) NOT NULL,
  `datetime` datetime(6) NOT NULL,
  `srcip` varchar(45) DEFAULT NULL,
  `srcport` varchar(45) DEFAULT NULL,
  `dstip` varchar(45) DEFAULT NULL,
  `dstport` varchar(45) DEFAULT NULL,
  `content` varchar(8000) DEFAULT NULL,
  PRIMARY KEY (`id`,`datetime`),
  KEY `callid` (`callid`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
```
In case sip-traffic is so high that the DELETEs of old records cannot keep up, I recommend
vertical partitioning : ``` ...PARTITION BY RANGE (to_days(`datetime`))... ```
with a script (php, python, etc.) you create new partitions and simply drop old ones automatically.

---
##### 3. edit the configuration-file `sipcollect.config`
```sh
###################################################
# configuration for mysql-access and libpcap-filter
###################################################
dbhost = "127.0.0.1"
dbname = "sipcollect"
dbuser = "sip"
dbpasswd = "********"
packet_filter = "(udp or tcp) and (port 5060 or port 5070 or port 5080)"
```
---

## USAGE
```sh
sudo ./sipcollect 1 
```
`"1"` stands for the interface number. If you start sipcollect without an argument it will list the available interfaces.
 
### 
### 
### 
### 
### 






