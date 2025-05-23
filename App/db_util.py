#
# database utilities. Hopefully isolating the db-specific code
#
# Rick Wightman, May 2023
#
import pymysql
import pymysql.cursors
import settings


#
# POST - specify object, return new Id
# GET(s) - no argument, return rows
# GET - Id, return row
# PUT - Id, Object, no return
# DELETE - Id, no return
def db_access(sqlProc, sqlArgs):
    try:
        dbConnection = pymysql.connect(
            host=settings.MYSQL_HOST,
            user=settings.MYSQL_USER,
            password=settings.MYSQL_PASSWORD,
            database=settings.MYSQL_DB,
            charset='utf8mb4',
            cursorclass= pymysql.cursors.DictCursor)
        cursor = dbConnection.cursor()
        cursor.callproc(sqlProc, sqlArgs)
        rows = cursor.fetchall()
        dbConnection.commit()
        cursor.close()
    except pymysql.MySQLError as e:
        raise Exception('Database Error:'+str(e))
    finally:
        dbConnection.commit()
        dbConnection.close()

    return rows
