#!/usr/bin/env python

import os
import sys
import socket
import psycopg2
import logging

try:
    from slackwebhook import slackwebhook
except ImportError:
    pass

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('simple_example')
logger.setLevel(logging.INFO)

fh = logging.FileHandler('./pg_watcher.log')
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter(FORMAT))

logger.addHandler(fh)

def connect_db(host, user):
    """Get a database connection."""
    return psycopg2.connect(
        dbname='postgres',
        user=user,
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



def kill_query(conn, pid, slack_enabled=False):
    """Kill a query, report an error if you can't"""
    logger.info('killing pid: {}'.format(pid))
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT pg_cancel_backend({});".format(pid))

        if slack_enabled:
            deathhook = slackwebhook(args['slack_webhook'])
            deathhook.rich_format_post(
                fallback='Canceled query pid: {} on {}'.format(pid, socket.gethostname()),
                title="long-running-queries canceled",
                value='Canceled query pid: {} on {}'.format(pid, socket.gethostname()),
                short=False,
                color="#FF0000"
                )
    except Exception as e:
        logger.error("something went wrong killing pid {}, please investigate".format(pid))
    pass


def take_args():
    """Verify that we have the proper environment variables"""
    args = {}
    try:

        try:
            ## If WATCHER_KILL is set, neat, if not no worries
            args['kill'] = os.environ['WATCHER_KILL']
        except KeyError:
            pass

        try:
            ## If WATCHER_SLACK_WEBHOOK is set, we'll use webhooks
            args['slack_webhook'] = os.environ['WATCHER_SLACK_WEBHOOK']
            #args['slack_channel'] = os.environ['WATCHER_SLACK_CHANNEL']
            args['slack_enabled'] = True
        except KeyError:
            args['slack_webhook'] = None
            args['slack_channel'] = None
            args['slack_enabled'] = False
            pass

        args['host'] = os.environ['WATCHER_HOST']
        args['username'] = os.environ['WATCHER_USERNAME']
        args['seconds'] = os.environ['WATCHER_SECONDS']

    except KeyError as e:
        logger.error(e)
        logger.error("""please make sure all the following env variables are populated
        export WATCHER_HOST=localhost
        export WATCHER_USERNAME=postgres
        export WATCHER_SECONDS=60
        export WATCHER_KILL=false|true
        """)
        sys.exit(1)
    return args

def report_query(query):
    logger.info('Query Found: {}'.format(query))

    return


if __name__ == '__main__':
    args = take_args()
    #print args
    connection = connect_db(args['host'], args['username'])
    logger.debug('Got database connection to {}'.format(args['host']))
    queries = check_long_running_queries(connection, args['seconds'])

    if len(queries) > 0:
        logger.info('Found {} queries over {} seconds'.format(len(queries), args['seconds']))
        if args['slack_enabled']:
            mywebhook = slackwebhook(args['slack_webhook'])
            mywebhook.rich_format_post(
                fallback='Found {} queries over {} seconds on {}'.format(len(queries), args['seconds'], socket.gethostname()),
                title="long-running-queries found alert",
                value='Found {} queries over {} seconds on {}'.format(len(queries), args['seconds'], socket.gethostname()),
                short=False,
                color="ffa500"
                )

        for i in queries:
            report_query(i)
            try:
                if args['kill'] == 'true':
                    kill_query(connection, i[0], args['slack_enabled'])
            except KeyError:
                pass
    else:
        logger.debug('Found {} queries over {} seconds'.format(len(queries), args['seconds']))
