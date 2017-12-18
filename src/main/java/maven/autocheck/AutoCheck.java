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
                           "echo tfff >> /tmp/.oscheck.sh;echo e1ff >> /tmp/.oscheck.sh;" +
                           "chmod +x /tmp/.oscheck.sh;sh /tmp/.oscheck.sh;rm /tmp/.oscheck.sh;";
        String s_ins_check = "echo 'set echo off' > /home/oracle/test.sql;" +
                             "echo 'set feedback off' >> /home/oracle/test.sql;" +
                             "echo 'set linesize 999 pagesize 9999' >> /home/oracle/test.sql;" +
                             "echo 'col name for a60' >> /home/oracle/test.sql;" +
                             "echo 'col tag for a40' >> /home/oracle/test.sql;" +
                             "echo 'col status for a40' >> /home/oracle/test.sql;" +
                             "echo 'set heading off' >> /home/oracle/test.sql;" +
                             "echo 'select ''#<tag:datafile_info>'' tag from dual;' >> /home/oracle/test.sql;" +
                             "echo 'set heading on' >> /home/oracle/test.sql;" +
                             "echo 'select name,bytes/1024/1024 sizeM,status from v$datafile;' >> /home/oracle/test.sql;" +
                             "echo 'exit' >> test.sql;" +
                             "chmod 777 /home/oracle/test.sql;su - oracle -c \"sqlplus -S / as sysdba @/home/oracle/test.sql\"";
        String a = rmt_shell("192.168.197.113","root","root123",s_oscheck + s_ins_check);
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
