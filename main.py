#!/usr/bin/env python

import os
import sys
import psycopg2
import logging

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('simple_example')
logger.setLevel(logging.INFO)

fh = logging.FileHandler('./pg_watcher.log')
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter(FORMAT))

logger.addHandler(fh)

def connect_db(host, user, password):
    """Get a database connection."""
    return psycopg2.connect(
        dbname='postgres',
        user=user,
        password=password,
        host=host
        )


def check_long_running_queries(conn, seconds):
    """Do the check to see how long queries are running"""

    # Here's what we run to check queries
    # The PID must be first for killing to work
    check_query = """
    SELECT pid,query,user,EXTRACT(EPOCH FROM (now() - query_start)) as time_running
    FROM pg_stat_activity
    WHERE state = 'active' AND EXTRACT(EPOCH FROM (now() - query_start)) > {};
    """.format(seconds)

    logger.debug("Query for long-running-queries: {}".format(check_query))
    try:
        cursor = conn.cursor()
        cursor.execute(check_query)
        queries = cursor.fetchall()
        return queries

    except psycopg2.ProgrammingError as e:
        logger.error(e)
        return []



def kill_query(conn, pid):
    """Kill a query, report an error if you can't"""
    logger.info('killing pid: {}'.format(pid))
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT pg_cancel_backend({});".format(pid))
    except Exception as e:
        logger.error("something went wrong killing pid {}, please investigate".format(pid))
    pass


def take_args():
    """Verify that we have the proper environment variables"""
    args = {}
    try:
        args['host'] = os.environ['WATCHER_HOST']
        args['username'] = os.environ['WATCHER_USERNAME']
        args['password'] = os.environ['WATCHER_PASSWORD']
        args['seconds'] = os.environ['WATCHER_SECONDS']
        try:
            ## If WATCHER_KILL is set, neat, if not no worries
            args['kill'] = os.environ['WATCHER_KILL']
        except KeyError:
            pass

    except KeyError as e:
        logger.error(e)
        logger.error("""please make sure all the following env variables are populated
        export WATCHER_HOST=localhost
        export WATCHER_USERNAME=user
        export WATCHER_PASSWORD=hello
        export WATCHER_SECONDS=60
        export WATCHER_KILL=false
        """)
        sys.exit(1)
    return args

def report_query():
    pass


if __name__ == '__main__':
    args = take_args()
    #print args
    connection = connect_db(args['host'], args['username'], args['password'])
    logger.debug('Got database connection to {}'.format(args['host']))
    queries = check_long_running_queries(connection, args['seconds'])

    if len(queries) > 0:
        logger.info('Found {} queries over {} seconds'.format(len(queries), args['seconds']))
        for i in queries:
            logger.info('Query Found: {}'.format(i))
            try:
                if args['kill'] == 'true':
                    kill_query(connection, i[0])
            except KeyError:
                pass
    else:
        logger.debug('Found {} queries over {} seconds'.format(len(queries), args['seconds']))
