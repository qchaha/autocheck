package maven.autocheck;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSetMetaData;
import java.util.*;
import java.text.SimpleDateFormat;
import java.io.InputStream;
import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;
import java.security.MessageDigest;
import java.net.*;
import java.util.regex.*;



public class AutoCheck{
    public static void main(String[] args )
    {
        String s_oscheck = "echo '#!/bin/sh' > /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:date>'\" >> /tmp/.oscheck.sh; echo date >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:hostname>'\" >> /tmp/.oscheck.sh; echo hostname >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:uname -a>'\" >>/tmp/.oscheck.sh; echo 'uname -a'>>/tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:cpuinfo>'\" >> /tmp/.oscheck.sh; echo cpu_count='$(cat /proc/cpuinfo | grep processor | wc -l)' >> /tmp/.oscheck.sh;echo cpu_model='$(cat /proc/cpuinfo | grep name | sed -n \"1p\")' >> /tmp/.oscheck.sh;echo 'echo ${cpu_count} X ${cpu_model#*: }' >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:free>'\" >> /tmp/.oscheck.sh; echo 'free -m' >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:df>'\" >> /tmp/.oscheck.sh; echo 'df -h' >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:vmstat>'\" >> /tmp/.oscheck.sh; echo 'vmstat 1 5' >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:lsnrctl>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"lsnrctl status\"' >> /tmp/.oscheck.sh;" +
                           "echo \"echo '#<tag:opath>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"\\$ORACLE_HOME/OPatch/opatch lsinv\"' >> /tmp/.oscheck.sh;" +
                           "echo tfff >> /tmp/.oscheck.sh;echo e1ff >> /tmp/.oscheck.sh;" +
                           "chmod +x /tmp/.oscheck.sh;sh /tmp/.oscheck.sh;rm /tmp/.oscheck.sh;";

        String s_ins_check = "echo 'set echo off' > /tmp/.inscheck.sql;" +
                             "echo 'set feedback off' >> /tmp/.inscheck.sql;" +
                             "echo 'set linesize 999 pagesize 50000' >> /tmp/.inscheck.sql;" +
                             "echo \"alter session set nls_date_format='yyyy-mm-dd hh24:mi:ss';\" >> /tmp/.inscheck.sql;" +
                             "echo 'col tag for a40' >> /tmp/.inscheck.sql;" +

                             "echo 'set heading off' >> /tmp/.inscheck.sql;" +
                             "echo \"select '#<tag:ins_startup_time>' tag from dual;\" >> /tmp/.inscheck.sql;" +
                             "echo 'set heading on' >> /tmp/.inscheck.sql;" +
                             "echo 'select startup_time from v$instance;' >> /tmp/.inscheck.sql;" +

                             "echo 'col sizeM for 999999.99' >> /tmp/.inscheck.sql;" +
                             "echo 'set heading off' >> /tmp/.inscheck.sql;" +
                             "echo \"select '#<tag:sga_info>' tag from dual;\" >> /tmp/.inscheck.sql;" +
                             "echo 'set heading on' >> /tmp/.inscheck.sql;" +
                             "echo 'select item,sum(bytes/1024/1024)sizeM from (select decode(pool,NULL,name,pool) item ,bytes from v$sgastat) group by item;' >> /tmp/.inscheck.sql;" +

                             "echo 'col value for a50' >> /tmp/.inscheck.sql;" +
                             "echo 'col name for a30' >> /tmp/.inscheck.sql;" +
                             "echo 'set heading off' >> /tmp/.inscheck.sql;" +
                             "echo \"select '#<tag:nondefault-para>' tag from dual;\" >> /tmp/.inscheck.sql;" +
                             "echo 'set heading on' >> /tmp/.inscheck.sql;" +
                             "echo \"select name,value from v\\$parameter where isdefault != 'TRUE';\" >> /tmp/.inscheck.sql;" +

                             "echo 'set heading off' >> /tmp/.inscheck.sql;" +
                             "echo \"select '#<tag:log_switchcount>' tag from dual;\" >> /tmp/.inscheck.sql;" +
                             "echo 'set heading on' >> /tmp/.inscheck.sql;" +
                             "echo \"select * from (select to_char (first_time, 'yyyy-mm-dd') day,count (recid) count_number,count (recid) * 200 size_mb from v\\$log_history group by to_char (first_time, 'yyyy-mm-dd') order by 1) where rownum < 20;\" >> /tmp/.inscheck.sql;" +

                             "echo 'exit' >> /tmp/.inscheck.sql;" +
                             "chmod 777 /tmp/.inscheck.sql;su - oracle -c \"sqlplus -S / as sysdba @/tmp/.inscheck.sql\";";

        String s_db_check = "echo 'set echo off' > /home/oracle/dbcheck.sql;" +
                            "echo 'set feedback off' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set linesize 999 pagesize 50000' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col tag for a40' >> /home/oracle/dbcheck.sql;" +

                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:database_version>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select banner from v$version;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col name for a80' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:ctrl_file_info>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select name from v$controlfile;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:database_version>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select banner from v$version;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col member for a80' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col status for a20' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col group# for 999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col thread# for 999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col sizeM for 99999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col members for 99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col status for a9' >> /home/oracle/dbcheck.sql;" +
                            "echo \"alter session set nls_date_format='yyyy-mm-dd hh24:mi:ss';\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:log_info>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select group#,status,type,member from v$logfile;' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select group#,thread#,sequence#,bytes/1024/1024 sizeM,members,archived,status,first_change#,first_time from v$log;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col tbs_name for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col tbs_sizeM for 9999999.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col used_sizeM for 9999999.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col free_sizeM for 9999999.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col use_ratio for 99.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:tbs_usage>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select a.a1 tbs_name,b.b2/1024/1024 tbs_sizeM,(b.b2-a.a2)/1024/1024 used_sizeM, a.a2/1024/1024 free_sizeM,substr((b.b2-a.a2)/b.b2*100,1,5) use_ratio from (select  tablespace_name a1, sum(nvl(bytes,0)) a2 from dba_free_space group by tablespace_name) a,(select tablespace_name b1,sum(bytes) b2 from dba_data_files group by tablespace_name) b,(select tablespace_name c1,contents c2,extent_management c3  from dba_tablespaces) c where a.a1=b.b1 and c.c1=b.b1;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col owner for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col original_name for a40' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col operation for 9999999999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col type for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col ts_name for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:recycle>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select owner,object_name,original_name,operation,type,ts_name,createtime,droptime from dba_recyclebin;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:corruption_block>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select count(*) corruption_count from v$database_block_corruption;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col object_name for a40' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col object_type for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:invalid_objects>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select object_name,object_type,owner,status from dba_objects where status = 'INVALID';\" >> /home/oracle/dbcheck.sql;" +

                            "echo 'col grantee for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col granted_role for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col admin_option for 9999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col default_role for 9999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:dba_role>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select * from dba_role_privs where granted_role = 'DBA';\" >> /home/oracle/dbcheck.sql;" +

                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:database_size>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select to_char(sum(bytes/1024/1024/1024),'9999999999.99') db_sizeG from dba_segments;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col name for a60' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col sizeM for 9999999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:datafile_info>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select name,status,bytes/1024/1024 sizeM from v$datafile;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col operation for a10' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:rman_info>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select  start_time, end_time, operation, output_bytes, status from v$rman_status order by end_time;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'col fname for a60' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col ts_name for a15' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col phyrds for 9999999999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col read_pct for 99.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col phywrts for 9999999999' >> /home/oracle/dbcheck.sql;" +
                            "echo 'col write_pct for 99.99' >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:datafile_io>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select * from (SELECT df.tablespace_name ts_name, df.file_name fname, fs.phyrds phyrds, (fs.phyrds * 100) / (fst.pr + tst.pr)  read_pct, fs.phywrts phywrts, (fs.phywrts * 100) / (fst.pw + tst.pw)   write_pct FROM sys.dba_data_files df , v$filestat fs , (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE df.file_id = fs.file# UNION SELECT tf.tablespace_name ts_name, tf.file_name fname, ts.phyrds phyrds,(ts.phyrds * 100) / (fst.pr + tst.pr)  read_pct, ts.phywrts  phywrts, (ts.phywrts * 100) / (fst.pw + tst.pw) write_pct FROM sys.dba_temp_files  tf, v$tempstat  ts, (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE tf.file_id = ts.file# ORDER BY phyrds DESC) where rownum < 10 ;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'exit' >> /home/oracle/dbcheck.sql;" +
                            "chmod 777 /home/oracle/dbcheck.sql;su - oracle -c \"sqlplus -S / as sysdba @/home/oracle/dbcheck.sql\"";

        String s_awr = "echo 'SPOOL /home/oracle/awr.txt'" +
                       "echo 'SET ECHO OFF' > /home/oracle/creawr.sql;" +
                       "echo 'SET VERI OFF' >> /home/oracle/creawr.sql;" +
                       "echo 'SET FEEDBACK OFF' >> /home/oracle/creawr.sql;" +
                       "echo 'SET TERMOUT ON' >> /home/oracle/creawr.sql;" +
                       "echo 'SET HEADING OFF' >> /home/oracle/creawr.sql;" +
                       "echo 'SET LINESIZE 9999 PAGESIZE 50000' >> /home/oracle/creawr.sql;" +

                       "echo 'VARIABLE dbid NUMBER' >> /home/oracle/creawr.sql;" +
                       "echo 'VARIABLE inst_num NUMBER' >> /home/oracle/creawr.sql;" +
                       "echo 'VARIABLE bid NUMBER' >> /home/oracle/creawr.sql;" +
                       "echo 'VARIABLE eid NUMBER' >> /home/oracle/creawr.sql;" +
                       "echo 'BEGIN' >> /home/oracle/creawr.sql;" +
                       //"echo \"SELECT MIN (snap_id) INTO :bid FROM dba_hist_snapshot WHERE TO_CHAR (end_interval_time, 'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /home/oracle/creawr.sql;" +
                       //"echo \"SELECT MAX (snap_id) INTO :eid FROM dba_hist_snapshot WHERE TO_CHAR (begin_interval_time,'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /home/oracle/creawr.sql;" +
                       "echo \"select '99'a into :eid from dual;\" >> /home/oracle/creawr.sql;" +
                       "echo \"select '97'b into :bid from dual;\" >> /home/oracle/creawr.sql;" +
                       "echo 'SELECT dbid INTO :dbid FROM v$database;' >> /home/oracle/creawr.sql;" +
                       "echo 'SELECT instance_number INTO :inst_num FROM v$instance;' >> /home/oracle/creawr.sql;" +
                       "echo 'END;' >> /home/oracle/creawr.sql;" +
                       "echo '/' >> /home/oracle/creawr.sql;" +
                       "echo 'SELECT output FROM TABLE (DBMS_WORKLOAD_REPOSITORY.awr_report_text(:dbid,:inst_num,:bid,:eid));' >> /home/oracle/creawr.sql;" +
                       "echo 'SPOOL OFF'" +

                       "echo 'exit' >> /home/oracle/creawr.sql;" +
                       "chmod 777 /home/oracle/creawr.sql;su - oracle -c \"sqlplus -S / as sysdba @/home/oracle/creawr.sql\"";

        String a = rmt_shell("192.168.197.113","root","root123",s_oscheck + s_ins_check + s_db_check + s_awr);
        System.out.println(a);
    }

    public static String f_date()
    {
        return "ff";
    }

    //远程调用shell
    public static String rmt_shell(String ip, String username, String password, String cmd)
    {
        String re = null;
        String line = null;
         try
        {
            /* Create a connection instance */
            //因为连接db已经有import java.sql.Connection，所以这里不能import ch.ethz.ssh2.Connection，要换个引用方法；
            ch.ethz.ssh2.Connection conn = new ch.ethz.ssh2.Connection(ip, 22);

            /* Now connect */

            conn.connect();

            /* Authenticate.
             * If you get an IOException saying something like
             * "Authentication method password not supported by the server at this stage."
             * then please check the FAQ.
             */

            boolean isAuthenticated = conn.authenticateWithPassword(username, password);

            if (isAuthenticated == false)
                throw new IOException("Authentication failed.");

            /* Create a session */

            Session sess = conn.openSession();

            sess.execCommand(cmd);

            /*
             * This basic example does not handle stderr, which is sometimes dangerous
             * (please read the FAQ).
             */

            InputStream stdout = new StreamGobbler(sess.getStdout());

            BufferedReader br = new BufferedReader(new InputStreamReader(stdout));

            while (true)
            {
                line = br.readLine();

                if (line == null)
                    break;

                if(re == null)
                {
                    re = line + "\r";
                }
                else
                {
                    re = re + line + "\r";
                }
            }

            /* Show exit status, if available (otherwise "null") */

            //System.out.println("ExitCode: " + sess.getExitStatus());

            /* Close this session */

            sess.close();

            /* Close the connection */

            conn.close();

        }
        catch (IOException e)
        {
            e.printStackTrace(System.err);
            System.exit(2);
        }
        //System.out.println(re);
        return re;
    }
}
