package maven.autocheck;
import java.io.IOException;
import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
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
    String s_check_cmd = f_check_shell();
    String s_check_result = f_rmt_shell("192.168.197.113","root","root123",s_check_cmd);
    //System.out.println(s_check_result);
    String s_filepath = "//usr/local//httpd-2.4.29//htdocs//bootstrap-4.0.0-beta.2//check.html";
    String s_code = f_write_file(f_struct_html(), s_filepath);
    System.out.println(s_code);
    System.out.println(f_search_log(s_check_result, "#<tag:date>"));
  }

  public static String f_struct_html(String s_db_name, String s_hostname, String s_section, String s_item, String s_log_record)
  {
    String s_html_header = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Autocheck</title><!-- 包含头部信息用于适应不同设备 --><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><!-- 包含 bootstrap 样式表 --><link href=\"dist/css/bootstrap.min.css\" rel=\"stylesheet\"></head>";

    String s_html_body = "<body>  <div class=\"container\">    <h2>" + s_section + ". " + s_db_name + "数据库系统检查</h2>    <pre></pre>    <pre></pre>    <h3>" + s_section + ".1 " + s_db_name + "1主机操作系统检查</h3>    <pre></pre>";
    return s_html_header + s_html_body;
  }

  public static String f_search_log(String s_check_result, String s_tag)
  {
     int i_begin,i_end;
     String s_retrun;
     i_begin = s_check_result.indexOf(s_tag);
     i_end = s_check_result.indexOf("#<tag:uname>");
     s_return = s_check_result.substring(i_begin, i_end);
     System.out.println(s_return);
  }

  public static String f_write_file(String s_content,String s_filepath)
  {
    try{
      File writename = new File(s_filepath);
      writename.createNewFile();
      BufferedWriter out = new BufferedWriter(new FileWriter(writename));
      out.write(s_content);
      out.close();
      return "finish!";
    }
    catch (Exception e) {
      e.printStackTrace();
      return "write html error!";
    }
  }

  public static String f_check_shell()
  {
    String s_oscheck =
    "echo '#!/bin/sh' > /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:date>'\" >> /tmp/.oscheck.sh; echo date >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:hostname>'\" >> /tmp/.oscheck.sh; echo hostname >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:uname>'\" >>/tmp/.oscheck.sh; echo 'uname -a'>>/tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:cpuinfo>'\" >> /tmp/.oscheck.sh; echo cpu_count='$(cat /proc/cpuinfo | grep processor | wc -l)' >> /tmp/.oscheck.sh;echo cpu_model='$(cat /proc/cpuinfo | grep name | sed -n \"1p\")' >> /tmp/.oscheck.sh;echo 'echo ${cpu_count} X ${cpu_model#*: }' >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:free>'\" >> /tmp/.oscheck.sh; echo 'free -m' >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:df>'\" >> /tmp/.oscheck.sh; echo 'df -h' >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:vmstat>'\" >> /tmp/.oscheck.sh; echo 'vmstat 1 5' >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:lsnrctl>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"lsnrctl status\"' >> /tmp/.oscheck.sh;" +
    "echo \"echo '#<tag:opath>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"\\$ORACLE_HOME/OPatch/opatch lsinv\"' >> /tmp/.oscheck.sh;" +
    "echo tfff >> /tmp/.oscheck.sh;echo e1ff >> /tmp/.oscheck.sh;" +
    "chmod +x /tmp/.oscheck.sh;sh /tmp/.oscheck.sh;rm /tmp/.oscheck.sh;";

    String s_ins_check =
    "echo 'set echo off' > /tmp/.inscheck.sql;" +
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
    "chmod 777 /tmp/.inscheck.sql;su - oracle -c \"sqlplus -S / as sysdba @/tmp/.inscheck.sql\";rm /tmp/.inscheck.sql;";

    String s_db_check =
    "echo 'set echo off' > /tmp/.dbcheck.sql;" +
    "echo 'set feedback off' >> /tmp/.dbcheck.sql;" +
    "echo 'set linesize 999 pagesize 50000' >> /tmp/.dbcheck.sql;" +
    "echo 'col tag for a40' >> /tmp/.dbcheck.sql;" +

    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:database_version>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select banner from v$version;' >> /tmp/.dbcheck.sql;" +

    "echo 'col name for a80' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:ctrl_file_info>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select name from v$controlfile;' >> /tmp/.dbcheck.sql;" +

    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:database_version>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select banner from v$version;' >> /tmp/.dbcheck.sql;" +

    "echo 'col member for a80' >> /tmp/.dbcheck.sql;" +
    "echo 'col status for a20' >> /tmp/.dbcheck.sql;" +
    "echo 'col group# for 999' >> /tmp/.dbcheck.sql;" +
    "echo 'col thread# for 999' >> /tmp/.dbcheck.sql;" +
    "echo 'col sizeM for 99999' >> /tmp/.dbcheck.sql;" +
    "echo 'col members for 99' >> /tmp/.dbcheck.sql;" +
    "echo 'col status for a9' >> /tmp/.dbcheck.sql;" +
    "echo \"alter session set nls_date_format='yyyy-mm-dd hh24:mi:ss';\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:log_info>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select group#,status,type,member from v$logfile;' >> /tmp/.dbcheck.sql;" +
    "echo 'select group#,thread#,sequence#,bytes/1024/1024 sizeM,members,archived,status,first_change#,first_time from v$log;' >> /tmp/.dbcheck.sql;" +

    "echo 'col tbs_name for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col tbs_sizeM for 9999999.99' >> /tmp/.dbcheck.sql;" +
    "echo 'col used_sizeM for 9999999.99' >> /tmp/.dbcheck.sql;" +
    "echo 'col free_sizeM for 9999999.99' >> /tmp/.dbcheck.sql;" +
    "echo 'col use_ratio for 99.99' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:tbs_usage>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select a.a1 tbs_name,b.b2/1024/1024 tbs_sizeM,(b.b2-a.a2)/1024/1024 used_sizeM, a.a2/1024/1024 free_sizeM,substr((b.b2-a.a2)/b.b2*100,1,5) use_ratio from (select  tablespace_name a1, sum(nvl(bytes,0)) a2 from dba_free_space group by tablespace_name) a,(select tablespace_name b1,sum(bytes) b2 from dba_data_files group by tablespace_name) b,(select tablespace_name c1,contents c2,extent_management c3  from dba_tablespaces) c where a.a1=b.b1 and c.c1=b.b1;' >> /tmp/.dbcheck.sql;" +

    "echo 'col owner for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col original_name for a40' >> /tmp/.dbcheck.sql;" +
    "echo 'col operation for 9999999999' >> /tmp/.dbcheck.sql;" +
    "echo 'col type for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col ts_name for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:recycle>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select owner,object_name,original_name,operation,type,ts_name,createtime,droptime from dba_recyclebin;' >> /tmp/.dbcheck.sql;" +

    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:corruption_block>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select count(*) corruption_count from v$database_block_corruption;' >> /tmp/.dbcheck.sql;" +

    "echo 'col object_name for a40' >> /tmp/.dbcheck.sql;" +
    "echo 'col object_type for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:invalid_objects>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo \"select object_name,object_type,owner,status from dba_objects where status = 'INVALID';\" >> /tmp/.dbcheck.sql;" +

    "echo 'col grantee for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col granted_role for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col admin_option for 9999' >> /tmp/.dbcheck.sql;" +
    "echo 'col default_role for 9999' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:dba_role>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo \"select * from dba_role_privs where granted_role = 'DBA';\" >> /tmp/.dbcheck.sql;" +

    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:database_size>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select to_char(sum(bytes/1024/1024/1024),'9999999999.99') db_sizeG from dba_segments;' >> /tmp/.dbcheck.sql;" +

    "echo 'col name for a60' >> /tmp/.dbcheck.sql;" +
    "echo 'col sizeM for 9999999' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:datafile_info>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select name,status,bytes/1024/1024 sizeM from v$datafile;' >> /tmp/.dbcheck.sql;" +

    "echo 'col operation for a10' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:rman_info>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select  start_time, end_time, operation, output_bytes, status from v$rman_status order by end_time;' >> /tmp/.dbcheck.sql;" +

    "echo 'col fname for a60' >> /tmp/.dbcheck.sql;" +
    "echo 'col ts_name for a15' >> /tmp/.dbcheck.sql;" +
    "echo 'col phyrds for 9999999999' >> /tmp/.dbcheck.sql;" +
    "echo 'col read_pct for 99.99' >> /tmp/.dbcheck.sql;" +
    "echo 'col phywrts for 9999999999' >> /tmp/.dbcheck.sql;" +
    "echo 'col write_pct for 99.99' >> /tmp/.dbcheck.sql;" +
    "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
    "echo \"select '#<tag:datafile_io>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
    "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
    "echo 'select * from (SELECT df.tablespace_name ts_name, df.file_name fname, fs.phyrds phyrds, (fs.phyrds * 100) / (fst.pr + tst.pr)  read_pct, fs.phywrts phywrts, (fs.phywrts * 100) / (fst.pw + tst.pw)   write_pct FROM sys.dba_data_files df , v$filestat fs , (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE df.file_id = fs.file# UNION SELECT tf.tablespace_name ts_name, tf.file_name fname, ts.phyrds phyrds,(ts.phyrds * 100) / (fst.pr + tst.pr)  read_pct, ts.phywrts  phywrts, (ts.phywrts * 100) / (fst.pw + tst.pw) write_pct FROM sys.dba_temp_files  tf, v$tempstat  ts, (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE tf.file_id = ts.file# ORDER BY phyrds DESC) where rownum < 10 ;' >> /tmp/.dbcheck.sql;" +

    "echo 'exit' >> /tmp/.dbcheck.sql;" +
    "chmod 777 /tmp/.dbcheck.sql;su - oracle -c \"sqlplus -S / as sysdba @/tmp/.dbcheck.sql\";rm /tmp/.dbcheck.sql;";

    String s_awr =
    "echo 'SET ECHO OFF' > /tmp/.creawr.sql;" +
    "echo 'SET VERI OFF' >> /tmp/.creawr.sql;" +
    "echo 'SET FEEDBACK OFF' >> /tmp/.creawr.sql;" +
    "echo 'SET TERMOUT ON' >> /tmp/.creawr.sql;" +
    "echo 'SET HEADING OFF' >> /tmp/.creawr.sql;" +
    "echo 'SET LINESIZE 120 PAGESIZE 50000' >> /tmp/.creawr.sql;" +

    "echo 'VARIABLE dbid NUMBER' >> /tmp/.creawr.sql;" +
    "echo 'VARIABLE inst_num NUMBER' >> /tmp/.creawr.sql;" +
    "echo 'VARIABLE bid NUMBER' >> /tmp/.creawr.sql;" +
    "echo 'VARIABLE eid NUMBER' >> /tmp/.creawr.sql;" +
    "echo 'BEGIN' >> /tmp/.creawr.sql;" +
    //"echo \"SELECT MIN (snap_id) INTO :bid FROM dba_hist_snapshot WHERE TO_CHAR (end_interval_time, 'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /tmp/.creawr.sql;" +
    //"echo \"SELECT MAX (snap_id) INTO :eid FROM dba_hist_snapshot WHERE TO_CHAR (begin_interval_time,'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /tmp/.creawr.sql;" +
    "echo \"select '99'a into :eid from dual;\" >> /tmp/.creawr.sql;" +
    "echo \"select '97'b into :bid from dual;\" >> /tmp/.creawr.sql;" +
    "echo 'SELECT dbid INTO :dbid FROM v$database;' >> /tmp/.creawr.sql;" +
    "echo 'SELECT instance_number INTO :inst_num FROM v$instance;' >> /tmp/.creawr.sql;" +
    "echo 'END;' >> /tmp/.creawr.sql;" +
    "echo '/' >> /tmp/.creawr.sql;" +
    "echo \"SPOOL /tmp/.awr.txt\" >> /tmp/.creawr.sql;" +
    "echo 'SELECT output FROM TABLE (DBMS_WORKLOAD_REPOSITORY.awr_report_text(:dbid,:inst_num,:bid,:eid));' >> /tmp/.creawr.sql;" +
    "echo \"SPOOL OFF\" >> /tmp/.creawr.sql;" +

    "echo 'exit' >> /tmp/.creawr.sql;" +
    "chmod 777 /tmp/.creawr.sql;su - oracle -c \"sqlplus -S / as sysdba @/tmp/.creawr.sql > /dev/null 2>&1\";" +

    "echo \"echo '<tag:top 5 event>' > /tmp/.awr_statistics.log\" > /tmp/.awr_statistics.sh;" +
    "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
    "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 5 Timed Events' | awk '{print \\$1}' | cut -d ':' -f 1)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e_num=\\$(echo \\${b_num}+8 | bc)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +

    "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
    "echo \"echo '<tag:top 5 sql>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
    "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by Elapsed Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 1p)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by Elapsed Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 2p)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e2_num=\\$(cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | awk '{print \\$1}' | grep -n '^[0-9]' | cut -d \":\" -f 1 | sed -n 6p)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e2_num=\\$(echo \\${e2_num} - 1 | bc)\" >> /tmp/.awr_statistics.sh;" +
    "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | sed -n \"8,\\${e2_num}p\" >> /tmp/.awr_statistics.log \" >> /tmp/.awr_statistics.sh;" +

    "echo \"echo '<tag:instance_performance>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
    "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
    "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'DB Name' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 5 Timed Events' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
    "echo \"e_num=\\$(echo \\${e_num}-1 | bc)\" >> /tmp/.awr_statistics.sh; " +
    "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
    "chmod +x /tmp/.awr_statistics.sh;sh /tmp/.awr_statistics.sh;cat /tmp/.awr_statistics.log;rm /tmp/.awr_statistics.sh;rm /tmp/.awr_statistics.log;rm /tmp/.awr.txt;";

    return s_oscheck + s_ins_check + s_db_check + s_awr;
  }

  //远程调用shell
  public static String f_rmt_shell(String ip, String username, String password, String cmd)
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
