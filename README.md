# sipcollect
collects sip-packets and stores them in mysql

sipcollect traces VoIP sip-messages, extracts the Call-ID and stores every individial message in a mysql-table.
Usually, Call-Detail-Records (CDR) of Voice Switches include the Call-ID of every Call-Leg.
By referencing to the mysql-records with that Call-ID you have all relevant signaling messages of that Call.
