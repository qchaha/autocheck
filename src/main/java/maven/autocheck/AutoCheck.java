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
                            "echo 'set heading off' >> /home/oracle/dbcheck.sql;" +
                            "echo \"select '#<tag:tbs_usage>' tag from dual;\" >> /home/oracle/dbcheck.sql;" +
                            "echo 'set heading on' >> /home/oracle/dbcheck.sql;" +
                            "echo 'select a.a1 tbs_name,b.b2/1024/1024 tbs_sizeM,(b.b2-a.a2)/1024/1024 used_sizeM, a.a2/1024/1024 free_sizeM,substr((b.b2-a.a2)/b.b2*100,1,5) use_ratio from (select  tablespace_name a1, sum(nvl(bytes,0)) a2 from dba_free_space group by tablespace_name) a,(select tablespace_name b1,sum(bytes) b2 from dba_data_files group by tablespace_name) b,(select tablespace_name c1,contents c2,extent_management c3  from dba_tablespaces) c where a.a1=b.b1 and c.c1=b.b1;' >> /home/oracle/dbcheck.sql;" +

                            "echo 'exit' >> /home/oracle/dbcheck.sql;" +
                            "chmod 777 /home/oracle/dbcheck.sql;su - oracle -c \"sqlplus -S / as sysdba @/home/oracle/dbcheck.sql\"";

        String a = rmt_shell("192.168.197.113","root","root123",s_oscheck + s_ins_check + s_db_check);
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
