from __future__ import print_function

import logging
import mysql.connector

logger = logging.getLogger(__name__)

#list of SQL statements to interface with mysql

db_statements = {
    'create_table': 'CREATE TABLE signatures (id int NOT NULL AUTO_INCREMENT, sid varchar(10) NOT NULL UNIQUE, raw varchar(8192) NOT NULL, header varchar(2000) NOT NULL, priority int, msg varchar(280), enabled BOOLEAN default TRUE, gid int, classtype varchar(140), rev int, proto varchar(140), primary key (id));',

    'insert_rule' : ("REPLACE INTO signatures "
                     "(sid, classtype, header, msg, rev, raw, enabled, proto, priority, gid) "
                     "VALUES (%(sid)s, %(classtype)s, %(header)s, %(msg)s, %(rev)s, %(raw)s, %(enabled)s, %(proto)s, %(priority)s, %(gid)s);"),

    'count_rules_enabled' : 'SELECT count(*) FROM signatures where enabled = TRUE;',
    'count_rules_disabled' : 'SELECT count(*) FROM signatures where enabled = FALSE;',
    'count_rules_total' : 'SELECT count(*) FROM signatures',

    'custom_query' : "UPDATE signatures set enabled = FALSE where proto like '%modbus%' or proto like '%dnp3%';" #eg to avoid protocol not supported error.
}

#Create a connection to a mysql database

def create_connection(mysql_conf_file=""):
    connection = mysql.connector.connect()
    try:
        connection = mysql.connector.connect(option_files=mysql_conf_file, auth_plugin='mysql_native_password')
        logger.info("Success. Connected to mysql database.")
    except Exception as err:
        logger.warning("Failed to get a connection to the database: %s" % err)

    return connection

#Create the database table if it does not exist

def create_rule_table(connection):
    cursor = connection.cursor()
    try:
        cursor.execute(db_statements['create_table'])
        connection.commit()
        logger.info("Success. Signature table created.")
    except Exception as e:
        logger.warning("Database table not created: %s" % e)
    cursor.close()

#Process the rules that were generated in the main function by executing SQL insert statements against the cursor and then commit to the connection.

def insert_rules(connection, rules):
    cursor = connection.cursor()
    success_count = 0
    total_rules = len(rules)
    logger.info("Inserting rules into the database.") # Let the user know that something is happening while the first rules are processed.
    for rule in rules:
        # Just check that there are no lists being passed into the database. It can't insert a list yet.
        for key, value in rule.items():
            if isinstance(value, list):
                rule[key] = str(rule[key])
        try:
            cursor.execute(db_statements['insert_rule'], rule) #Insert a rule into the database.
            success_count = success_count + 1
            if success_count % 1000 == 0:
                logger.info("Successfully added %s rules." % success_count)
        except mysql.connector.IntegrityError as err: #Duplicate. Some additional logic could be supplied to deal with that, but we use REPLACE if to take the newer version violates the unique constriant on SID.
            logger.info("Something wrong with inserting rule: %s " %err)
        except Exception as err: #Error. Report that rule wasn't inserted into the database.
            logger.info("Failed to insert rule into database: " + str(rule['sid']) + " " + str(err))

    connection.commit() #Commit once to the database. Important or else the data won't be committed.
    cursor.close()

#Report some stats about the rules we have.

def get_database_stats(connection):
    cursor = connection.cursor()
    cursor.execute(db_statements['count_rules_enabled'])
    for value in cursor:
        logger.info("# Enabled rules in the database: %s" % value)
    cursor.execute(db_statements['count_rules_disabled'])
    for value in cursor:
        logger.info("# Disabled rules in the database: %s" % value)
    cursor.execute(db_statements['count_rules_total'])
    for value in cursor:
        logger.info("# Total rules in the database: %s" % value)
    cursor.close()

#Run a custom query to post-process the results. This is optional & exists to clean up the database after re-adding rules.

def run_custom_query(connection):
    cursor = connection.cursor()
    cursor.execute(db_statements['custom_query'])
    connection.commit()
    cursor.close()
