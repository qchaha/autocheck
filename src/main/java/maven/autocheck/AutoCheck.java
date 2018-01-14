package maven.autocheck;
import java.io.*;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSetMetaData;
import java.util.*;
import java.text.SimpleDateFormat;
import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;
import java.security.MessageDigest;
import java.net.*;
import java.util.regex.*;



public class AutoCheck{
  public static void main(String[] args )
  {
    String s_code = null;                //the return code of generate check report
    String s_file_dir = null;            //project path,all file in there
    String s_file_name = null;           //check report name

    s_file_dir = "//usr//local//httpd-2.4.29//htdocs//bootstrap-3.3.7//";
    s_file_name = "check.html";

    //f_struct_html(s_file_dir , s_file_name);
    f_write_file(f_struct_html(s_file_dir , s_file_name), s_file_dir + s_file_name);

    //System.out.println(f_rmt_shell("192.168.197.142","administrator","1qaz@WSX","wmic cpu list brief"));
    //f_write_file(f_rmt_shell("192.168.197.142","administrator","1qaz@WSX","chcp 437 && systeminfo"),"//tmp//ff.txt");

  }

  public static String f_check(String s_tag, String s_line, String s_os_type)
  {
    //s_line = "Available Physical Memory: 754 MB";
    //s_tag = "#<tag:vmstat>";
    String s_red_prefix = "<span style=\"color:red;font-weight:bold\">";
    String s_red_postfix = "</span>";
    String s_return = null;
    Pattern p = null;
    Matcher m = null;
    String s_format_string = null;
    int alert_count = 0;                      //oracle数据库实例告警日志数量
    int warning_count = 0;                    //vmstat, 同行数据中，警告替换位置需要加 warning*48
    int usage = 0;                            //df文件系统使用率的百分比
    int i_col_num = 0;                        //用于正则表达式匹配时，区分不同列（不同指标值）
    StringBuffer strbuff = null;              //Stringbuffer,用来构造字符串非常灵活，replace()能够选择起始和结束为止

    //各指标阀值
    double d_free_warning = 1.1;                       //空闲内存百分比
    int i_df_warning = 20;                             //文件系统使用率
    int i_vmstat_waitp_warning = 25;                   //等待进程数
    int i_vmstat_idle_warning = 95;                    //CPU空闲值
    int i_vmstat_waitio_warning = 30;                  //io等待值
    int i_vmstat_solaris_free_memory = 2048000;        //solaris下vmstat中的空闲内存
    int i_tbs_usage_warning = 85;                      //表空间使用率百分比
    int i_db_corruption_blocks = 0;                    //损坏文件块
    float i_t5sql_exe_per_s = 0;                       //每次执行sql所需时间
    double d_windows_df_warning = 0.15;                 //windows文件系统可用空间和总空间比率

    if( s_os_type.equals("linux") )
    {
      switch(s_tag)
      {
        case "#<tag:top 5 sql>":
        p = Pattern.compile("\\d+[.]\\d+\\s+");
        m = p.matcher(s_line);
        strbuff = new StringBuffer(s_line);
        while( m.find() )
        {
          if( i_col_num == 0)
          {
            if(Float.parseFloat(m.group(0)) >= i_t5sql_exe_per_s)
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
            }
            s_return = strbuff.toString();
          }
          else
          {
            s_return = strbuff.toString();
          }
          i_col_num++;
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:rman_info>":
        p = Pattern.compile("FAILED|ERRORS|WARNINGS");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).indexOf("FAILED") != -1 || m.group(0).indexOf("ERRORS") != -1 || m.group(0).indexOf("WARNINGS") != -1 )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:datafile_info>":
        p = Pattern.compile("OFFLINE|RECOVER|SYSOFF|ONLINE|SYSTEM");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).equals("OFFLINE") || m.group(0).equals("RECOVER") || m.group(0).equals("SYSOFF") )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:corruption_block>":
        p = Pattern.compile("\\d+$");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( Integer.parseInt(m.group(0)) > i_db_corruption_blocks )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:tbs_usage>":
        strbuff = new StringBuffer(s_line);
        p = Pattern.compile("([1-9]\\d*\\.?\\d*$)|(\\.\\d*[1-9])$");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).indexOf(".") == -1 )
          {
            if( Integer.parseInt( m.group(0) ) >= i_tbs_usage_warning )
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
              s_return = strbuff.toString();
            }
            else
            {
              s_return = s_line;
            }
          }
          else if( m.group(0).indexOf(".") != -1 )
          {
            if( Integer.parseInt( m.group(0).substring(0, m.group(0).indexOf(".")) ) >= i_tbs_usage_warning )
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
              s_return = strbuff.toString();
            }
            else
            {
              s_return = s_line;
            }
          }
        }
        if( s_return == null )
        {
          s_return = s_line;
        }
        //s_return = strbuff.toString();
        break;


        case "#<tag:alertlog_dest>":
        alert_count = s_line.indexOf("ORA-");
        if( alert_count != -1 )
        {
          s_return = s_red_prefix + s_line + s_red_postfix;
        }
        else
        {
          s_return = s_line;
        }
        break;

        case "#<tag:vmstat>":

        strbuff = new StringBuffer(s_line);

        //去掉前两行非数字数值
        if( !s_line.substring(0,1).equals("p") && !s_line.substring(1,2).equals("r") )
        {
          //匹配有边界的数字
          p = Pattern.compile("\\d+\\b");
          m = p.matcher(s_line);

          while(m.find())
          {
            //wait processes
            if( i_col_num == 0)
            {
              if(Integer.parseInt(m.group(0)) >= i_vmstat_waitp_warning)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            //idle
            else if( i_col_num == 14 )
            {
              if(Integer.parseInt(m.group(0)) <= i_vmstat_idle_warning)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            //io wait
            else if( i_col_num == 15 )
            {
              if(Integer.parseInt(m.group(0)) >= i_vmstat_waitio_warning)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            else
            {
              s_return = strbuff.toString();
            }
            i_col_num++;
            //System.out.println(s_front_str+"  " + s_red_prefix + m.group(0) + s_red_postfix + "   "+s_back_str);
            //System.out.println(s_return);
          }
        }
        else
        {
          s_return = strbuff.toString();
        }
        //System.out.println(strbuff);
        break;

        case "#<tag:free>":
        String s_array[] = null;
        double d_total = 0;
        double d_free = 0;
        if(s_line.substring(0,1).equals("S") || s_line.substring(0,1).equals("-"))
        {
          p = Pattern.compile("\\s+");
          m = p.matcher(s_line.substring(s_line.indexOf(":") + 1));
          s_format_string = m.replaceAll(" ");
          s_array = s_format_string.trim().split(" ");
          //匹配 这一行 ： -/+ buffers/cache:
          if(s_array.length == 2)
          {
            d_total = Integer.parseInt(s_array[0]) + Integer.parseInt(s_array[1]);
            d_free = Integer.parseInt(s_array[1]);
          }
          //匹配 这一行： Swap:
          else if(s_array.length == 3)
          {
            d_total = Integer.parseInt(s_array[1]) + Integer.parseInt(s_array[2]);
            d_free = Integer.parseInt(s_array[2]);
          }
          //System.out.println(d_free / d_total);
          if( d_free / d_total <= d_free_warning )
          {
            p = Pattern.compile("\\d+$");
            m = p.matcher(s_line.substring(s_line.indexOf(":") + 1));
            while( m.find() )
            {
              //System.out.println(m.group(0));
              if(s_array.length == 2)
              {
                s_return = s_line.replaceAll("\\d+$",s_red_prefix + s_array[1] + s_red_postfix);
              }
              else if(s_array.length == 3)
              {
                s_return = s_line.replaceAll("\\d+$",s_red_prefix + s_array[2] + s_red_postfix);
              }
            }
          }
          else
          {
            s_return = s_line;
          }
        }
        else
        {
          s_return = s_line;
        }
        break;

        case "#<tag:df>":
        p = Pattern.compile("\\d+%");
        m = p.matcher(s_line);
        while(m.find())
        {
          s_format_string = m.group(0);
          //去掉%号
          usage = Integer.parseInt(m.group(0).substring(0, m.group(0).length() - 1));
        }
        if(usage >= i_df_warning)
        {
          s_return = s_line.replaceAll(s_format_string, s_red_prefix + s_format_string + s_red_postfix);
        }
        else
        {
          s_return = s_line;
        }
        //System.out.println(s_return);
        break;

        default:
        s_return = s_line;
        break;
      }
    }
    else if( s_os_type.equals("solaris") )
    {
      switch (s_tag)
      {
        case "#<tag:df>":
        p = Pattern.compile("\\d+%");
        m = p.matcher(s_line);
        while(m.find())
        {
          s_format_string = m.group(0);
          //去掉%号
          usage = Integer.parseInt(m.group(0).substring(0, m.group(0).length() - 1));
        }
        if(usage >= i_df_warning)
        {
          s_return = s_line.replaceAll(s_format_string, s_red_prefix + s_format_string + s_red_postfix);
        }
        else
        {
          s_return = s_line;
        }
        break;


        case "#<tag:vmstat>":
        strbuff = new StringBuffer(s_line);

        //去掉前两行非数字数值
        if( !s_line.substring(1,2).equals("k") && !s_line.substring(1,2).equals("r") )
        {
          //匹配有边界的数字
          p = Pattern.compile("\\d+\\b");
          m = p.matcher(s_line);

          while(m.find())
          {
            //wait processes
            if( i_col_num == 0)
            {
              if(Integer.parseInt(m.group(0)) >= i_vmstat_waitp_warning)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            //idle
            else if( i_col_num == 21 )
            {
              if(Integer.parseInt(m.group(0)) <= i_vmstat_idle_warning)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            //usable memory
            else if( i_col_num == 4 )
            {
              if(Integer.parseInt(m.group(0)) <= i_vmstat_solaris_free_memory)
              {
                strbuff.replace(m.start() + 48 * warning_count, m.end() + 48 * warning_count, s_red_prefix + m.group(0) + s_red_postfix);
                warning_count++;
              }
              s_return = strbuff.toString();
            }
            else
            {
              s_return = strbuff.toString();
            }
            i_col_num++;
            //System.out.println(s_front_str+"  " + s_red_prefix + m.group(0) + s_red_postfix + "   "+s_back_str);
            //System.out.println(s_return);
          }
        }
        else
        {
          s_return = strbuff.toString();
        }
        break;

        case "#<tag:alertlog_dest>":
        alert_count = s_line.indexOf("ORA-");
        if( alert_count != -1 )
        {
          s_return = s_red_prefix + s_line + s_red_postfix;
        }
        else
        {
          s_return = s_line;
        }
        break;

        case "#<tag:top 5 sql>":
        p = Pattern.compile("\\d+[.]\\d+\\s+");
        m = p.matcher(s_line);
        strbuff = new StringBuffer(s_line);
        while( m.find() )
        {
          if( i_col_num == 0)
          {
            if(Float.parseFloat(m.group(0)) >= i_t5sql_exe_per_s)
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
            }
            s_return = strbuff.toString();
          }
          else
          {
            s_return = strbuff.toString();
          }
          i_col_num++;
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:rman_info>":
        p = Pattern.compile("FAILED|ERRORS|WARNINGS");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).indexOf("FAILED") != -1 || m.group(0).indexOf("ERRORS") != -1 || m.group(0).indexOf("WARNINGS") != -1 )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:datafile_info>":
        p = Pattern.compile("OFFLINE|RECOVER|SYSOFF|ONLINE|SYSTEM");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).equals("OFFLINE") || m.group(0).equals("RECOVER") || m.group(0).equals("SYSOFF") )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:corruption_block>":
        p = Pattern.compile("\\d+$");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( Integer.parseInt(m.group(0)) > i_db_corruption_blocks )
          {
            s_return = s_red_prefix + s_line + s_red_postfix;
          }
          else
          {
            s_return = s_line;
          }
        }
        //匹配表头两行,直接输入
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:tbs_usage>":
        strbuff = new StringBuffer(s_line);
        p = Pattern.compile("([1-9]\\d*\\.?\\d*$)|(\\.\\d*[1-9])$");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( m.group(0).indexOf(".") == -1 )
          {
            if( Integer.parseInt( m.group(0) ) >= i_tbs_usage_warning )
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
              s_return = strbuff.toString();
            }
            else
            {
              s_return = s_line;
            }
          }
          else if( m.group(0).indexOf(".") != -1 )
          {
            if( Integer.parseInt( m.group(0).substring(0, m.group(0).indexOf(".")) ) >= i_tbs_usage_warning )
            {
              strbuff.replace(m.start(), m.end(), s_red_prefix + m.group(0) + s_red_postfix);
              s_return = strbuff.toString();
            }
            else
            {
              s_return = s_line;
            }
          }
        }
        if( s_return == null )
        {
          s_return = s_line;
        }
        //s_return = strbuff.toString();
        break;

        default:
        s_return = s_line;
        break;
      }
    }
    else if( s_os_type.equals("windows") )
    {
      switch(s_tag)
      {
        case "#<tag:free>":
        if( s_line.indexOf("Available Physical Memory") != -1 )
        {
          p = Pattern.compile("(\\d+[,]\\d+\\sMB)|(\\d+\\sMB)");
          m = p.matcher(s_line);
          while( m.find() )
          {
            if( m.group(0).indexOf(",") != -1 )
            {
              if( Integer.parseInt(m.group(0).substring(0, (m.group(0).length() - 3)).replace(",","")) < 2000  )
              {
                s_return = s_line.replace(m.group(0), s_red_prefix + m.group(0) + s_red_postfix);
              }
              else
              {
                s_return = s_line;
              }
            }
            else
            {
              if( Integer.parseInt(m.group(0).substring(0, m.group(0).length() - 3)) < 2000 )
              {
                s_return = s_line.replace(m.group(0), s_red_prefix + m.group(0) + s_red_postfix);
              }
              else
              {
                s_return = s_line;
              }
            }
          }
        }
        else
        {
          s_return = s_line;
        }
        break;

        case "#<tag:df>":
        p = Pattern.compile("\\d+\\b");
        m = p.matcher(s_line);
        String s_temp = null;
        while( m.find() )
        {
          if( i_col_num == 0 )
          {
            s_temp = m.group(0);
          }
          if( i_col_num == 1 )
          {
            if( Double.parseDouble(s_temp) / Double.parseDouble(m.group(0)) <= d_windows_df_warning)
            {
              s_return = s_line.replace(s_temp, s_red_prefix + s_temp + s_red_postfix);
            }
            else
            {
              s_return = s_line;
            }
          }
          i_col_num++;
        }
        if( s_return == null )
        {
          s_return = s_line;
        }
        break;


        case "#<tag:vmstat>":
        strbuff = new StringBuffer(s_line);
        p = Pattern.compile("(CPU\\d+)(.*)(\\d+)");
        m = p.matcher(s_line);
        while( m.find() )
        {
          if( Integer.parseInt(m.group(3)) >= 0 )
          {
            strbuff.replace(m.start(3), m.end(3), s_red_prefix + m.group(3) + s_red_postfix);
            s_return = strbuff.toString();
          }
          else
          {
            s_return = s_line;
          }
        }
        if( s_return == null )
        {
          s_return = s_line;
        }

        break;

        default:
        s_return = s_line;
        break;
      }
    }
    return s_return;
  }


  public static String f_struct_html(String s_file_dir , String s_file_name)
  {
    String s_config_name = null;         //check config name,will be replaced of db in future
    String s_check_cmd = null;           //check command
    String s_check_result = null;        //fetch all check result
    String s_doc_info[] = null;            //storage all the config value in config.ini spilted by space
    String s_host_info[] = null;            //storage all the config value in config.ini spilted by space
    String s_html_header = null;         //html_header
    String s_html_cover = null;          //html_cover
    String s_html_summary = null;         //check_summary
    String s_html_body = null;           //html_body
    String s_html_foot = null;           //html_footer

    int machine_count = 0;               //how many machine will be checked
    Pattern p = null;
    Matcher m = null;                    //matcher pattern config.ini

    SimpleDateFormat df = new SimpleDateFormat("yyyy.MM.dd");

    //读取文件，找出主机信息（如ip，账号密码）和文档信息（如作者、客户名）
    s_config_name = "config.ini";
    p = Pattern.compile("<host_info>.+</host_info>");
    m = p.matcher(f_read_file(s_file_dir + s_config_name));
    while(m.find())
    {
      s_host_info = ((m.group(0).substring(11, m.group(0).length()-12)).trim()).split(" ");
    }
    p = Pattern.compile("<doc_info>.+</doc_info>");
    m = p.matcher(f_read_file(s_file_dir + s_config_name));
    while(m.find())
    {
      s_doc_info = ((m.group(0).substring(10, m.group(0).length()-11)).trim()).split(" ");
    }

    machine_count = s_host_info.length / 8;
    s_html_header = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Autocheck</title><!-- 包含头部信息用于适应不同设备 --><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><!-- 包含 bootstrap 样式表 --><link href=\"dist/css/bootstrap.min.v3.3.7-modify.css\" rel=\"stylesheet\"><link href=\"dist/css/bootstrap-table.css\" rel=\"stylesheet\"></head>";
    s_html_foot = "</div></body></html>";


    s_html_cover = "<body><div style=\"background-color:#F9F9F9\"><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br></div><div class=\"container-customize\"><p style=\"font-size:600%; text-align:center; margin:350px 0 0 0\">" + s_doc_info[0] + "</p><p style=\"font-size:600%; text-align:center; margin:30px 0 0 0\">数据库巡检报告</p><p style=\"font-size:300%; text-align:center; margin:700px 0 0 0\">广州市威盛软件有限公司</p><p style=\"font-size:260%; text-align:center; margin:20px 0 0 0\">" + df.format(new Date()) + "</p><br><br><br><br><br></div><div style=\"background-color:#F9F9F9\"><br><br><br><br><br><br></div><div class=\"container-customize\"><div style=\"background-color:#fff\"><br><br><br><br><br><br><br><br><br><p style=\"font-size:150%; text-align:right;\">" + s_doc_info[0] + "数据库巡检报告<hr></div><div class=\"table-responsive table-big1\"><p style=\"font-size:260%; text-align:left; margin:100px 0 50px 0\">文档控制：</p><p style=\"font-size:150%; text-align:left; margin:30px 0 50px 0\">更改记录：</p><table class=\"table table-striped table-bordered \" style=\"width: 70%; margin: 0 0 80px 0\"><thead><tr><th width=\"25%\">日期</th><th width=\"25%\">作者</th><th width=\"25%\">职位</th><th width=\"25%\">版本</th></tr></thead><tbody><tr><td>" + df.format(new Date()) + "</td><td>" + s_doc_info[1] + "</td><td>" + s_doc_info[2] + "</td><td>" + s_doc_info[3] +  "</td></tr><tr><td><br></td><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td><td><br></td></tr></tbody></table><p style=\"font-size:150%; text-align:left; margin:30px 0 50px 0\">文档审阅：</p><table class=\"table table-striped table-bordered\" style=\"width: 60%; margin: 0 0 80px 0\"><thead><tr><th width=\"25%\">姓名</th><th width=\"25%\">职位</th><th width=\"25%\">时间</th></tr></thead><tbody><tr><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td></tr></tbody></table><p style=\"font-size:150%; text-align:left; margin:30px 0 50px 0\">文档分发：</p><table class=\"table table-striped table-bordered\" style=\"width: 70%; margin: 0 0 650px 0\"><thead><tr><th width=\"25%\">接收单位</th><th width=\"25%\">姓名</th><th width=\"25%\">版本</th><th width=\"25%\">时间</th></tr></thead><tbody><tr><td>" + s_doc_info[0] + "</td><td><br></td><td>" + s_doc_info[3] + "</td><td>" + df.format(new Date()) + "</td></tr><tr><td><br></td><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td><td><br></td></tr></tbody></table></div></div></div><div class=\"container-customize\"><div style=\"background-color:#fff\"><br><br><br><br><br><br><br><br><br><p style=\"font-size:150%; text-align:right;\">" + s_doc_info[0] + "数据库巡检报告<hr></div><div class=\"table-responsive table-big1\"><p style=\"font-size:260%; text-align:left; margin:100px 0 50px 0\">设备列表：</p><table class=\"table table-striped table-bordered\" style=\"width: 70%; margin: 0 0 80px 0\"><thead><tr><th width=\"10%\">序号</th><th width=\"25%\">IP地址</th><th width=\"20%\">操作系统</th><th width=\"20%\">数据库软件</th><th width=\"25%\">数据库实例名</th></tr></thead><tbody>";
    //循环生成设备列表
    for(int cur = 0; cur < machine_count; cur++)
    {
      s_html_cover = s_html_cover + "<tr><td>" + Integer.toString(cur + 1) + "</td><td>" + s_host_info[ cur * 8 ] + "</td><td>" + s_host_info[ cur * 8 + 3 ] + "</td><td>" + s_host_info[ cur * 8 + 4 ] + " " + s_host_info[ cur * 8 + 5 ] + "</td><td>" + s_host_info[ cur * 8 + 7 ] + "</td></tr>";
    }
    if( machine_count <= 2 )
    {
      s_html_cover = s_html_cover + "<tr><td><br></td><td><br></td><td><br></td><td><br></td><td><br></td></tr><tr><td><br></td><td><br></td><td><br></td><td><br></td><td><br></td></tr></tbody></table></div></div>";
    }
    else
    {
      s_html_cover = s_html_cover + "</tbody></table></div></div>";
    }

    //详细巡检日志
    //根据设备列表循环巡检并生成报告
    for(int cur = 0; cur < machine_count; cur++)
    {
      s_check_cmd = f_check_shell(s_host_info[ cur * 8 + 3 ], s_host_info[ cur * 8 + 4 ], s_host_info[ cur * 8 + 5 ], s_host_info[ cur * 8 + 6 ], s_host_info[ cur * 8 + 7 ]);
      //System.out.println(s_check_cmd);
      s_check_result = f_rmt_shell(s_host_info[ cur * 8 ], s_host_info[ cur * 8 + 1 ], s_host_info[ cur * 8 + 2 ], s_check_cmd);
      //System.out.println(s_check_result);
      if(s_html_body == null)
      {
        s_html_body = f_struct_body(s_check_result, cur + 1, s_host_info[ cur * 8 + 3 ], s_host_info[ cur * 8 + 4 ], s_host_info[ cur * 8]);
      }
      else
      {
        s_html_body = s_html_body + f_struct_body(s_check_result, cur + 1, s_host_info[ cur * 8 + 3 ], s_host_info[ cur * 8 + 4 ], s_host_info[ cur * 8]);
      }
    }




    //巡检总结,根据详细巡检日志，找出问题项，再填写巡检总结，返回时放在详细巡检日志前
    s_html_summary = "<div class=\"container-customize\"><div class=\"table-responsive table-big1\"><p style=\"font-size:260%; text-align:left; margin:100px 0 50px 0\">巡检总结：</p>";

    for( int cur = 0; cur < machine_count; cur++ )
    {
      s_html_summary = s_html_summary + "<h2 style=\"margin:0 0 30px 0\">" + Integer.toString(cur + 1) + ". " + s_host_info[ cur * 8 + 7 ] + "数据库系统</h2><table class=\"table table-bordered\" style=\" margin: 0 0 80px 0\"><thead><tr><th width=\"5%\">序号</th><th width=\"15%\">主机IP</th><th width=\"10%\">巡检内容</th><th width=\"15%\">巡检结果</th><th width=\"50%\">情况说明</th></tr></thead><tbody>";

      for( int content = 0; content < 3; content++ )
      {
        s_html_summary = s_html_summary + "<tr><td style=\"vertical-align: middle\">" + String.valueOf(content + 1) + "</td>";

        if( content == 0 )
        {
          s_html_summary = s_html_summary + "<td rowspan=\"3\" style=\"vertical-align: middle\">" + s_host_info[ cur * 8 ] + "</td><td style=\"vertical-align: middle\">操作系统</td><td style=\"vertical-align: middle;\">";
        }
        else if( content == 1 )
        {
          s_html_summary = s_html_summary + "<td style=\"vertical-align: middle\">数据库实例</td><td style=\"vertical-align: middle;\">";
        }
        else if( content == 2 )
        {
          s_html_summary = s_html_summary + "<td style=\"vertical-align: middle\">数据库</td><td style=\"vertical-align: middle;\">";
        }
       if( s_html_body.indexOf("<!--tag: mARk for waRniNg iN tAblE <" + s_host_info[ cur * 8 ] + ":" + String.valueOf(content) + ":") != -1 )
       {
         int i_warning_count = 0;
        p = p.compile("(<!--tag: mARk for waRniNg iN tAblE <" + s_host_info[ cur * 8 ] + ":" + String.valueOf(content) + ":)(.{3,8})(> -->)");
        m = p.matcher(s_html_body);
        s_html_summary = s_html_summary + "<p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-warning\"><span class=\"glyphicon glyphicon-warning-sign\">警告</p></td><td style=\"vertical-align\">";
        while( m.find() )
        {
          i_warning_count++;
          //System.out.println(m.group(2));
          switch(m.group(2))
          {
            case "内存使用情况":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space: pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".系统内存率使用较高，建议关闭不必要的应用或者进行内存扩容，详见巡检日志的\"<b>内存使用情况</b>\"检查项目。</pre>";
            break;

            case "文件系统使用情况":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space: pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".文件系统使用率较高，建议清理不必要的文件或者进行文件系统扩容，详见巡检日志的\"<b>文件系统使用情况</b>\"检查项目。</pre>";
            break;

            case "系统负载":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space: pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".操作系统负载较高，建议与系统管理员联系，详见巡检日志的\"<b>表空间使用情况</b>\"检查项目。</pre>";
            break;

            case "实例警告日志":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space: pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".数据库实例日志近段时间存在警告，建议与数据库管理员联系，详见巡检日志的\"<b>实例警告日志</b>\"检查项目。</pre>";
            break;

            case "表空间使用情况":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space: pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".数据库表空间使用率较高，建议清理失效对象和回收站对象，或者进行表空间扩容，详见巡检日志的\"<b>表空间使用情况</b>\"检查项目。</pre>";
            break;

            case "RMAN备份情况":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space:pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".近段时间数据库RMAN备份出现警告，建议与数据库管理员联系，详见巡检日志的\"<b>RMAN备份情况</b>\"检查项目。</pre>";
            break;

            case "Top 5 SQL":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space:pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".数据库实例存在较长耗时SQL，建议与数据库管理员联系，详见巡检日志的\"<b>Top 5 SQL</b>\"检查项目。</pre>";
            break;

            case "损坏数据块信息":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space:pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".数据库存在损坏数据块，建议与数据库管理员联系，详见巡检日志的\"<b>损坏数据块信息</b>\"检查项目。</pre>";
            break;

            case "数据文件状态":
            s_html_summary = s_html_summary + "<pre style=\"font-size: 100%; white-space:pre-wrap; font-family: inherit;\">" + String.valueOf(i_warning_count) + ".数据库存在离线或需要恢复的数据文件，建议与数据库管理员联系，详见巡检日志的\"<b>数据文件状态</b>\"检查项目。</pre>";
            break;

            default :

            break;
          }
        }
        s_html_summary = s_html_summary + "</td></tr>";
      }
        else
        {
          switch(content)
          {
            case 0:
            s_html_summary = s_html_summary + "<p class=\"btn btn-success\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-warning-sign\">警告</p></td><td style=\"vertical-align: middle\">操作系统运行情况良好</td></tr>";
            break;
            case 1:
            s_html_summary = s_html_summary + "<p class=\"btn btn-success\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-warning-sign\">警告</p></td><td style=\"vertical-align: middle\">数据库实例运行情况良好</td></tr>";
            break;
            case 2:
            s_html_summary = s_html_summary + "<p class=\"btn btn-success\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-warning-sign\">警告</p></td><td style=\"vertical-align: middle\">数据库运行情况良好</td></tr>";
            break;
            default:
            break;
          }
        }
      }
      s_html_summary = s_html_summary + "</tbody></table>";
    }

    s_html_summary = s_html_summary + "</div></div><div class=\"container-customize\"><p style=\"font-size:320%; text-align:left; margin:100px 0 50px 0\">详细巡检日志：</p>";


    return s_html_header + s_html_cover + s_html_summary + s_html_body + s_html_foot;
  }

  public static String f_struct_body(String s_check_result, int i_section1, String s_os_type, String s_check_type, String s_host_ip)
  {
    BufferedReader b_reader = null;
    String s_return = null;
    String s_record = null;
    String s_item = null;
    String s_line = null;
    String s_title_name = null;
    String s_table_type[] = {"OS","INSTANCE","DATABASE"};
    String s_item_os[] = null;
    String s_item_instance[] = null;
    String s_item_db[] = null;
    String s_cursor[] = null;
    int i_table_type = 0;
    int i_item_type = 0;
    int i_section2 = 1;
    boolean is_ok = true;

    if( s_check_type.equals("sqlserver") )
    {
      s_item_os = new String[] {"检查时间","主机名","内核版本","CPU信息","内存使用情况","网络配置","文件系统使用情况","系统负载"};
      s_item_instance = new String[] {"实例启动时间","实例服务器名","实例服务名","实例CPU活动情况","实例内存分配情况","实例启动参数","Top 5 SQL"};
      s_item_db = new String[] {"数据库版本","数据库大小","日志文件信息","数据文件读写情况","数据库锁和等待","活动用户和进程信息","数据库登录名信息","查看数据库用户角色"};
      s_title_name = f_search_log(s_check_result,"#<tag:ins_service_name>");
      //System.out.println(s_title_name);
      s_title_name = s_title_name.substring(s_title_name.lastIndexOf("-") + 2 , s_title_name.length() - 2);
    }
    else if( s_check_type.equals("oracle") )
    {
      s_item_os = new String[] {"检查时间","主机名","内核版本","CPU信息","内存使用情况","网络配置","文件系统使用情况","系统负载"};
      s_item_instance = new String[] {"实例启动时间","实例警告日志","实例补丁","SGA共享内存信息","PGA共享内存信息","登录会话统计","实例归档信息","实例非默认参数","联机日志切换频率","实例性能统计","Top5 等待事件","Top 5 SQL"};
      s_item_db = new String[] {"数据库名", "数据库版本", "控制文件信息", "日志文件信息", "表空间使用情况", "回收站对象", "损坏数据块信息", "失效对象统计", "DBA授权", "数据库大小", "数据文件状态", "数据文件I/O统计分布", "RMAN备份情况"};
      s_title_name = f_search_log(s_check_result,"#<tag:database_name>");
      s_title_name = s_title_name.substring(s_title_name.lastIndexOf("-") + 2 , s_title_name.length() - 2);
    }
    //System.out.println(s_check_type);

    s_return = "<h2>" + String.valueOf(i_section1) + ". " + s_title_name + "数据库系统</h2><pre></pre><pre></pre>";

    //检查类别，不同的类型用s_cursor来穷举不同的检查项
    while( i_table_type < s_table_type.length )
    {
      if( i_table_type == 0 )
      {
        i_item_type = 0;
        s_cursor = s_item_os;
        s_return = s_return + "<h3>" + String.valueOf(i_section1) + "." + String.valueOf(i_section2) + " " + s_title_name + "主机操作系统检查</h3><pre></pre>";
      }
      else if( i_table_type == 1 )
      {
        i_item_type = 0;
        s_cursor = s_item_instance;
        s_return = s_return + "<h3>" + String.valueOf(i_section1) + "." + String.valueOf(i_section2) + " " + s_title_name + "数据库实例检查</h3><pre></pre>";
      }
      else if( i_table_type == 2 )
      {
        i_item_type = 0;
        s_cursor = s_item_db;
        s_return = s_return + "<h3>" + String.valueOf(i_section1) + "." + String.valueOf(i_section2) + " " + s_title_name + "数据库检查</h3><pre></pre>";
      }

      s_return = s_return + "<div class=\"table-responsive\"><table class=\"table table-striped table-bordered\"><thead><tr><th width=\"15%\"><h4><b>检查项目</h4></th><th width=\"70%\"><h4><b>检查结果</h4></th><th width=\"15%\"><h4><b>检查结论</h4></th></tr></thead><tbody>";

      //根据不同检查项，构建body
      while( i_item_type < s_cursor.length )
      {
        //reset status key
        is_ok = true;

        s_record = f_search_log(s_check_result, f_item_record_map(s_cursor[i_item_type]));
        //System.out.println(s_record);

        s_return = s_return + "<tr><td style=\"vertical-align: middle\">" + s_cursor[i_item_type] + "</td><td style=\"vertical-align: middle\">";

        try
        {
          b_reader = new BufferedReader(new StringReader(s_record));
          b_reader.readLine();
          while ((s_line = b_reader.readLine()) != null)
          {
            s_line = f_check(f_item_record_map(s_cursor[i_item_type]), s_line, s_os_type);
            s_return = s_return + "<pre style=\"white-space:pre-wrap\">" + s_line + "</pre>";
            //只要有红色标记，就是异常状态
            if( s_line.indexOf("color:red") == -1 && is_ok == true)
            {
              is_ok = true;
            }
            else
            {
              is_ok = false;
            }
          }
        }
        catch(IOException e)
        {
          e.printStackTrace();
        }
        if( is_ok == true )
        {
          s_return = s_return + "</td><td style=\"vertical-align: middle;\"><p class=\"btn btn-success\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-warning-sign\">警告</p></td></tr>";
        }
        else
        {
          s_return = s_return + "</td><td style=\"vertical-align: middle\",\"\"><p class=\"btn btn-customize\"><span class=\"glyphicon glyphicon-ok\">正常</p>&nbsp;&nbsp;&nbsp;&nbsp;<p class=\"btn btn-warning\"><span class=\"glyphicon glyphicon-warning-sign\"><!--tag: mARk for waRniNg iN tAblE <" + s_host_ip + ":" + String.valueOf(i_table_type) + ":" + s_cursor[i_item_type] + "> -->警告</p></td></tr>";
        }

        i_item_type++;

      }

      s_return = s_return + "</tbody></table></div><pre></pre><pre></pre>";
      i_table_type++;
      i_section2++;
    }
    return s_return;
  }

  public static String f_item_record_map(String s_item)
  {
    String s_map = null;
    switch(s_item)
    {
      case "检查时间":
      s_map = "#<tag:date>";
      break;
      case "主机名":
      s_map = "#<tag:hostname>";
      break;
      case "内核版本":
      s_map = "#<tag:uname>";
      break;
      case "CPU信息":
      s_map = "#<tag:cpuinfo>";
      break;
      case "内存使用情况":
      s_map = "#<tag:free>";
      break;
      case "网络配置":
      s_map = "#<tag:ifconfig>";
      break;
      case "文件系统使用情况":
      s_map = "#<tag:df>";
      break;
      case "系统负载":
      s_map = "#<tag:vmstat>";
      break;
      case "实例启动时间":
      s_map = "#<tag:ins_startup_time>";
      break;
      case "实例警告日志":
      s_map = "#<tag:alertlog_dest>";
      break;
      case "实例补丁":
      s_map = "#<tag:opatch>";
      break;
      case "SGA共享内存信息":
      s_map = "#<tag:sga_info>";
      break;
      case "PGA共享内存信息":
      s_map = "#<tag:pga_info>";
      break;
      case "登录会话统计":
      s_map = "#<tag:session_count>";
      break;
      case "实例归档信息":
      s_map = "#<tag:archivelog>";
      break;
      case "实例非默认参数":
      s_map = "#<tag:nondefault-para>";
      break;
      case "联机日志切换频率":
      s_map = "#<tag:log_switchcount>";
      break;
      case "实例性能统计":
      s_map = "#<tag:instance_performance>";
      break;
      case "Top5 等待事件":
      s_map = "#<tag:top 5 event>";
      break;
      case "Top 5 SQL":
      s_map = "#<tag:top 5 sql>";
      break;
      case "数据库名":
      s_map = "#<tag:database_name>";
      break;
      case "数据库版本":
      s_map = "#<tag:database_version>";
      break;
      case "控制文件信息":
      s_map = "#<tag:ctrl_file_info>";
      break;
      case "日志文件信息":
      s_map = "#<tag:log_info>";
      break;
      case "表空间使用情况":
      s_map = "#<tag:tbs_usage>";
      break;
      case "回收站对象":
      s_map = "#<tag:recycle>";
      break;
      case "损坏数据块信息":
      s_map = "#<tag:corruption_block>";
      break;
      case "失效对象统计":
      s_map = "#<tag:invalid_objects>";
      break;
      case "DBA授权":
      s_map = "#<tag:dba_role>";
      break;
      case "数据库大小":
      s_map = "#<tag:database_size>";
      break;
      case "数据文件状态":
      s_map = "#<tag:datafile_info>";
      break;
      case "RMAN备份情况":
      s_map = "#<tag:rman_info>";
      break;
      case "数据文件I/O统计分布":
      s_map = "#<tag:datafile_io>";
      break;
      case "实例服务名":
      s_map = "#<tag:ins_service_name>";
      break;
      case "实例服务器名":
      s_map = "#<tag:ins_server_name>";
      break;
      case "实例CPU活动情况":
      s_map = "#<tag:cpu_busy_status>";
      break;
      case "实例内存分配情况":
      s_map = "#<tag:instance memory usage>";
      break;
      case "实例启动参数":
      s_map = "#<tag:ins_startup_parameter>";
      break;
      case "数据文件读写情况":
      s_map = "#<tag:disk_io_status>";
      break;
      case "数据库锁和等待":
      s_map = "#<tag:dblock_status>";
      break;
      case "活动用户和进程信息":
      s_map = "#<tag:active_user_info>";
      break;
      case "数据库登录名信息":
      s_map = "#<tag:user_login_info>";
      break;
      case "查看数据库用户角色":
      s_map = "#<tag:user_role_info>";
      break;
      default:
      s_map = "undefined item!";
      break;
    };
    return s_map;
  }

  public static String f_search_log(String s_check_result, String s_tag)
  {
    //定位两个#<tag之间的内容>
    int i_begin,i_end,i_length;
    String s_return;
    i_begin = s_check_result.indexOf(s_tag);
    if( i_begin == -1 )
    {
      s_return = "no record!";
    }
    //第一个#<tag
    else if( i_begin == 0 )
    {
      s_return = s_check_result;
    }
    else
    {
      s_return = s_check_result.substring(i_begin);
    }
    i_length = s_return.indexOf("#<tag:", s_return.indexOf("#<tag:") + 1);
    //最后一个#<tag
    if( i_length == -1 )
    {
      s_return = s_return;
    }
    else
    {
      i_end = i_begin + i_length;
      s_return = s_check_result.substring(i_begin, i_end);
    }
    return s_return;
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

  public static String f_read_file(String s_config_path)
  {
    File filename = new File(s_config_path);
    String s_line = "";
    String s_return = null;
    BufferedReader bufferedReader = null;
    try
    {
      bufferedReader = new BufferedReader(new FileReader(filename));
      while((s_line = bufferedReader.readLine()) != null)
      {
        if(s_return == null)
        {
          s_return = s_line;
        }
        else
        {
          s_return = s_return + s_line;
        }
      }
      bufferedReader.close();
    }
    catch(IOException e)
    {
      e.printStackTrace();
      s_return = "read config file failure!";
    }
    return s_return;
  }

  public static String f_check_shell(String s_os_type, String s_appliance_type, String s_version, String s_options, String s_insname)
  {
    String s_awr_top_event = null;
    String s_awr_top_sql = null;
    String s_awr_performance = null;
    String s_oscheck = null;
    String s_ins_check = null;
    String s_db_check = null;
    String s_awr = null;

    if( s_appliance_type.equals("oracle") && s_version.equals("10g") )
    {
      s_awr_top_sql =
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"echo '#<tag:top 5 sql>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by Elapsed Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 1p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by CPU Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 1p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e2_num=\\$(cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | awk '{print \\$1}' | grep -n '^[0-9]' | cut -d \":\" -f 1 | sed -n 6p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e2_num=\\$(echo \\${e2_num} - 1 | bc)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | sed -n \"8,\\${e2_num}p\" >> /tmp/.awr_statistics.log \" >> /tmp/.awr_statistics.sh;" ;
    }
    else if( s_appliance_type.equals("oracle") && s_version.equals("11g") )
    {
      s_awr_top_sql =
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"echo '#<tag:top 5 sql>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by Elapsed Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 1p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'SQL ordered by CPU Time' | awk '{print \\$1}' | cut -d ':' -f 1  | sed -n 1p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e2_num=\\$(cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | awk '{print \\$1}' | grep -n '^[0-9]' | cut -d \":\" -f 1 | sed -n 6p)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e2_num=\\$(echo \\${e2_num} - 1 | bc)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" | sed -n \"11,\\${e2_num}p\" >> /tmp/.awr_statistics.log \" >> /tmp/.awr_statistics.sh;";
    }

    if( s_appliance_type.equals("oracle") && s_version.equals("10g") )
    {
      s_awr_top_event =
      "echo \"echo '#<tag:top 5 event>' > /tmp/.awr_statistics.log\" > /tmp/.awr_statistics.sh;" +
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 5 Timed Events' | awk '{print \\$1}' | cut -d ':' -f 1)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(echo \\${b_num}+8 | bc)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" ;
    }
    else if( s_appliance_type.equals("oracle") && s_version.equals("11g") )
    {
      s_awr_top_event =
      "echo \"echo '#<tag:top 5 event>' > /tmp/.awr_statistics.log\" > /tmp/.awr_statistics.sh;" +
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 10 Foreground Events by Total Wait Time' | awk '{print \\$1}' | cut -d ':' -f 1)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(echo \\${b_num}+9 | bc)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" ;
    }

    if( s_appliance_type.equals("oracle") && s_version.equals("10g") )
    {
      s_awr_performance =
      "echo \"echo '#<tag:instance_performance>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'DB Name' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 5 Timed Events' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(echo \\${e_num}-1 | bc)\" >> /tmp/.awr_statistics.sh; " +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" ;
    }
    else if( s_appliance_type.equals("oracle") && s_version.equals("11g") )
    {
      s_awr_performance =
      "echo \"echo '#<tag:instance_performance>' >> /tmp/.awr_statistics.log \">> /tmp/.awr_statistics.sh;" +
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'DB Name' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(cat /tmp/.awr.txt  | grep -in 'Top 10 Foreground Events by Total Wait Time' | awk '{print \\$1}' | cut -d ':' -f 1 )\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(echo \\${e_num}-1 | bc)\" >> /tmp/.awr_statistics.sh; " +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" ;
    }



    if( s_os_type.equals("linux") )
    {
      s_oscheck =
      "echo '#!/bin/sh' > /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:date>'\" >> /tmp/.oscheck.sh; echo date >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:hostname>'\" >> /tmp/.oscheck.sh; echo hostname >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:uname>'\" >>/tmp/.oscheck.sh; echo 'uname -a'>>/tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:cpuinfo>'\" >> /tmp/.oscheck.sh; echo cpu_count='$(cat /proc/cpuinfo | grep processor | wc -l)' >> /tmp/.oscheck.sh;echo cpu_model='$(cat /proc/cpuinfo | grep name | sed -n \"1p\")' >> /tmp/.oscheck.sh;echo 'echo ${cpu_count} X ${cpu_model#*: }' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:free>'\" >> /tmp/.oscheck.sh; echo 'free -m' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:ifconfig>'\" >> /tmp/.oscheck.sh; echo 'interface_count=$(ifconfig | grep -i hwaddr | wc -l)' >> /tmp/.oscheck.sh; echo 'while [ $interface_count -gt 0 ]' >> /tmp/.oscheck.sh;echo 'do' >> /tmp/.oscheck.sh;echo \"ip=\\$(ifconfig | grep 'inet addr' | awk '{print \\$2}' | sed -n \"\\${interface_count}p\")\" >> /tmp/.oscheck.sh; echo 'ip=${ip#*:}' >> /tmp/.oscheck.sh; echo \"i_name_mac=\\$(ifconfig | grep -i hwaddr | awk '{print \\$1 \\\" : \\\" \\$4\\\": \\\"\\$5}' | sed -n \"\\${interface_count}p\")\" >> /tmp/.oscheck.sh;echo 'echo \"$i_name_mac ip: $ip\"' >> /tmp/.oscheck.sh;echo 'interface_count=$(echo \"${interface_count}-1\" | bc)' >> /tmp/.oscheck.sh;echo 'done' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:df>'\" >> /tmp/.oscheck.sh; echo 'df -h' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:vmstat>'\" >> /tmp/.oscheck.sh; echo 'vmstat 1 5' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:lsnrctl>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"lsnrctl status\"' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:opatch>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"\\$ORACLE_HOME/OPatch/opatch lsinv | awk NF\"' >> /tmp/.oscheck.sh;" +

      //"chmod +x /tmp/.oscheck.sh;sh /tmp/.oscheck.sh;rm /tmp/.oscheck.sh;";
      "chmod +x /tmp/.oscheck.sh;sh /tmp/.oscheck.sh;";
    }
    else if( s_os_type.equals("solaris") )
    {
      s_oscheck =
      "echo '#!/bin/bash' > /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:date>'\" >> /tmp/.oscheck.sh; echo date >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:hostname>'\" >> /tmp/.oscheck.sh; echo hostname >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:uname>'\" >>/tmp/.oscheck.sh; echo 'uname -a'>>/tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:cpuinfo>'\" >> /tmp/.oscheck.sh; echo cpu_count='$(psrinfo | wc -l)' >> /tmp/.oscheck.sh;echo cpu_model='cpu_model=$(psrinfo -v | grep -i \"operates\")' >> /tmp/.oscheck.sh;echo 'echo \"${cpu_count} X ${cpu_model#*: }\"| sed \"s/,/ /g\"' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:free>'\" >> /tmp/.oscheck.sh; echo 'echo ::memstat | mdb -k' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:ifconfig>'\" >> /tmp/.oscheck.sh; echo 'interface_count=$(ifconfig -a | grep -i ether | wc -l)' >> /tmp/.oscheck.sh; echo 'while [ $interface_count -gt 0 ]' >> /tmp/.oscheck.sh;echo 'do' >> /tmp/.oscheck.sh;echo \"ip=\\$(ifconfig -a | grep -v 127.0.0.1 | grep -v lo0 | grep 'inet' | awk '{print \\$2}' | sed -n \"\\${interface_count}p\")\" >> /tmp/.oscheck.sh; echo 'ip=${ip#*:}' >> /tmp/.oscheck.sh; echo \"adapter_name=\\$(ifconfig -a | grep -v 127.0.0.1 | grep -v lo0 | grep -i flags= | awk '{print \\$1}' | sed -n \"\\${interface_count}p\")\">> /tmp/.oscheck.sh;echo \"i_name_mac=\\$(ifconfig -a | grep -v 127.0.0.1 | grep -v lo0 | grep -i ether | awk '{print \\$2}' | sed -n \"\\${interface_count}p\")\" >> /tmp/.oscheck.sh;echo 'echo \"$adapter_name $i_name_mac ip: $ip\"' >> /tmp/.oscheck.sh;echo 'interface_count=$(echo \"${interface_count}-1\" | bc)' >> /tmp/.oscheck.sh;echo 'done' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:df>'\" >> /tmp/.oscheck.sh; echo 'df -h' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:vmstat>'\" >> /tmp/.oscheck.sh; echo 'vmstat 1 5' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:lsnrctl>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"lsnrctl status\" | grep -v SunOS' >> /tmp/.oscheck.sh;" +
      "echo \"echo '#<tag:opatch>'\" >> /tmp/.oscheck.sh;echo 'su - oracle -c \"\\$ORACLE_HOME/OPatch/opatch lsinv | awk '/./' \" | grep -v SunOS' >> /tmp/.oscheck.sh;" +

      //"chmod +x /tmp/.oscheck.sh;bash /tmp/.oscheck.sh ; rm /tmp/.oscheck.sh;";
      "chmod +x /tmp/.oscheck.sh;bash /tmp/.oscheck.sh ;";
    }
    else if( s_os_type.equals("windows") )
    {
      s_oscheck =
      "chcp 437 > nul & " +
      "echo #^<tag:date^> && echo %date:~0,10% - %time% &" +
      "echo #^<tag:hostname^> && hostname &" +
      "echo #^<tag:uname^> & systeminfo | findstr /b /c:\"OS Version\" &" +
      "echo #^<tag:cpuinfo^> & systeminfo | findstr /C \"Processor(s) Mhz\"  &" +
      "echo #^<tag:free^> & systeminfo | findstr Memory &" +
      "echo #^<tag:ifconfig^> &  wmic nicconfig get IPAddress,Description | findstr [0-9][0-9][0-9].[0-9][0-9][0-9].[0-9][0-9][0-9].[0-9][0-9][0-9] & " +
      "echo #^<tag:df^> & wmic LOGICALDISK where \"DriveType=3\" get DeviceID,Size,FreeSpace,Description,FileSystem &" +
      "echo #^<tag:vmstat^> & wmic cpu get DeviceID,Caption,loadpercentage & ";
    }


    if( s_appliance_type.equals("oracle") )
    {
      s_ins_check =
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
      "echo \"select * from (select to_char (first_time, 'yyyy-mm-dd') day,count (recid) count_number,count (recid) * 200 size_mb from v\\$log_history group by to_char (first_time, 'yyyy-mm-dd') order by 1) where rownum < 10;\" >> /tmp/.inscheck.sql;" +

      "echo 'set heading off' >> /tmp/.inscheck.sql;" +
      "echo \"select '#<tag:session_count>' tag from dual;\" >> /tmp/.inscheck.sql;" +
      "echo 'set heading on' >> /tmp/.inscheck.sql;" +
      "echo \"select count(*)session_count from v\\$session;\" >> /tmp/.inscheck.sql;" +

      "echo 'set heading off' >> /tmp/.inscheck.sql;" +
      "echo \"select '#<tag:archivelog>' tag from dual;\" >> /tmp/.inscheck.sql;" +
      "echo 'set heading on' >> /tmp/.inscheck.sql;" +
      "echo \"archive log list;\" >> /tmp/.inscheck.sql;" +

      "echo 'exit' >> /tmp/.inscheck.sql;" +

      //check alertlog
      "echo \"alert_path=\\$(su - oracle -c \\\"sqlplus -S / as sysdba <<EOF\" > /tmp/.alertcheck.sh;" +
      "echo 'set echo off' >> /tmp/.alertcheck.sh;" +
      "echo 'set feedback off' >> /tmp/.alertcheck.sh;" +
      "echo 'set heading off' >> /tmp/.alertcheck.sh;" +
      "echo \"select value from v\\\\\\\\\\\\\\$parameter where name ='background_dump_dest';\" >> /tmp/.alertcheck.sh;" +
      "echo \"EOF\\\"| awk '/./' | grep -v SunOS);\" >> /tmp/.alertcheck.sh;" +
      "echo \"tail -2000 \\$alert_path/alert*log | grep ORA-\" >> /tmp/.alertcheck.sh;" +

      //"chmod 777 /tmp/.inscheck.sql;su - oracle -c \"export ORACLE_SID=" + s_insname + ";sqlplus -S / as sysdba @/tmp/.inscheck.sql\" | grep -v SunOS;rm /tmp/.inscheck.sql;";
      "chmod 777 /tmp/.inscheck.sql;su - oracle -c \"export ORACLE_SID=" + s_insname + ";sqlplus -S / as sysdba @/tmp/.inscheck.sql\" | grep -v SunOS;chmod +x /tmp/.alertcheck.sh;echo -e '\\n#<tag:alertlog_dest>';bash /tmp/.alertcheck.sh;";
    }
    else if( s_appliance_type.equals("sqlserver") )
    {
      s_ins_check =
      "echo #^<tag:ins_server_name^> && sqlcmd -Q \"set nocount on;select ltrim(@@servername) ServerName\" -Y 20 &&" +
      "echo #^<tag:ins_service_name^> && sqlcmd -Q \"set nocount on;select ltrim(@@servicename) ServiceName\" -Y 20 &&" +
      "echo #^<tag:ins_startup_time^> && sqlcmd -Q \"set nocount on;select convert(varchar(30),login_time,120) startup_time from master..sysprocesses where spid=1\" &&" +
      "echo #^<tag:cpu_busy_status^> && sqlcmd -Q \"set nocount on;select @@cpu_busy*cast(@@timeticks as float)/1000 [              CPU BUSY(S)],@@idle*cast(@@timeticks as float)/1000 [              CPU IDLE(S)]\" -Y 10 &&" +
      "echo #^<tag:instance memory usage^> && sqlcmd -Q \"set nocount on;select counter_name,cntr_value from sysperfinfo where counter_name like '%Memory%'\" -Y 35 &&" +
      "echo #^<tag:ins_startup_parameter^> && sqlcmd -Q \"exec sp_configure\" &&" +
      "echo #^<tag:top 5 sql^> && sqlcmd -Q \"set nocount on;with maco as(select top 5 plan_handle,sum(total_worker_time) as total_worker_time ,sum(execution_count) as execution_count ,count(1) as sql_count from sys.dm_exec_query_stats group by plan_handle order by sum(total_worker_time) desc) select t.text ,a.total_worker_time ,a.execution_count ,a.sql_count from maco a cross apply sys.dm_exec_sql_text(plan_handle) t\" -y 50 &&";
    }

    if( s_appliance_type.equals("oracle") )
    {
      s_db_check =
      "echo 'set echo off' > /tmp/.dbcheck.sql;" +
      "echo 'set feedback off' >> /tmp/.dbcheck.sql;" +
      "echo 'set linesize 999 pagesize 50000' >> /tmp/.dbcheck.sql;" +
      "echo 'col tag for a40' >> /tmp/.dbcheck.sql;" +

      "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
      "echo \"select '#<tag:database_name>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
      "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
      "echo 'select name from v$database;' >> /tmp/.dbcheck.sql;" +

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

      "echo 'col owner for a8' >> /tmp/.dbcheck.sql;" +
      "echo 'col original_name for a13' >> /tmp/.dbcheck.sql;" +
      "echo 'col operation for a9' >> /tmp/.dbcheck.sql;" +
      "echo 'col type for a8' >> /tmp/.dbcheck.sql;" +
      "echo 'col ts_name for a8' >> /tmp/.dbcheck.sql;" +
      "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
      "echo \"select '#<tag:recycle>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
      "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
      "echo 'select owner,object_name,original_name,operation,type,ts_name,droptime from dba_recyclebin;' >> /tmp/.dbcheck.sql;" +

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
      "echo 'col status for a27' >> /tmp/.dbcheck.sql;" +
      "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
      "echo \"select '#<tag:rman_info>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
      "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
      "echo 'select  start_time, end_time, operation, output_bytes, status from v$rman_status order by end_time;' >> /tmp/.dbcheck.sql;" +

      "echo 'col fname for a50' >> /tmp/.dbcheck.sql;" +
      "echo 'col ts_name for a10' >> /tmp/.dbcheck.sql;" +
      "echo 'col phyrds for 9999999999' >> /tmp/.dbcheck.sql;" +
      "echo 'col read_pct for 99.99' >> /tmp/.dbcheck.sql;" +
      "echo 'col phywrts for 9999999999' >> /tmp/.dbcheck.sql;" +
      "echo 'col write_pct for 99.99' >> /tmp/.dbcheck.sql;" +
      "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
      "echo \"select '#<tag:datafile_io>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
      "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
      "echo 'select * from (SELECT df.tablespace_name ts_name, df.file_name fname, fs.phyrds phyrds, (fs.phyrds * 100) / (fst.pr + tst.pr)  read_pct, fs.phywrts phywrts, (fs.phywrts * 100) / (fst.pw + tst.pw)   write_pct FROM sys.dba_data_files df , v$filestat fs , (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE df.file_id = fs.file# UNION SELECT tf.tablespace_name ts_name, tf.file_name fname, ts.phyrds phyrds,(ts.phyrds * 100) / (fst.pr + tst.pr)  read_pct, ts.phywrts  phywrts, (ts.phywrts * 100) / (fst.pw + tst.pw) write_pct FROM sys.dba_temp_files  tf, v$tempstat  ts, (select sum(f.phyrds) pr, sum(f.phywrts) pw from v$filestat f) fst, (select sum(t.phyrds) pr, sum(t.phywrts) pw from v$tempstat t) tst WHERE tf.file_id = ts.file# ORDER BY phyrds DESC) where rownum < 10 ;' >> /tmp/.dbcheck.sql;" +

      "echo 'set heading off' >> /tmp/.dbcheck.sql;" +
      "echo \"select '#<tag:for-solaris-iso-banner>' tag from dual;\" >> /tmp/.dbcheck.sql;" +
      "echo 'set heading on' >> /tmp/.dbcheck.sql;" +
      "echo 'select sysdate from dual;' >> /tmp/.dbcheck.sql;" +

      "echo 'exit' >> /tmp/.dbcheck.sql;" +
      //"chmod 777 /tmp/.dbcheck.sql;su - oracle -c \"export ORACLE_SID=" + s_insname + ";sqlplus -S / as sysdba @/tmp/.dbcheck.sql \"| grep -v SunOS;rm /tmp/.dbcheck.sql;";
      "chmod 777 /tmp/.dbcheck.sql;su - oracle -c \"export ORACLE_SID=" + s_insname + ";sqlplus -S / as sysdba @/tmp/.dbcheck.sql \"| grep -v SunOS;";
    }
    else if (s_appliance_type.equals("sqlserver"))
    {
      s_db_check =
      "echo #^<tag:database_version^> && sqlcmd -Q \"select @@version[version]\" -Y 100 | findstr \"SQL Server\" &&" +
      "echo #^<tag:database_size^> && sqlcmd -Q \"with fs as(select database_id, type, size * 8.0 / 1024 size from sys.master_files)select name,(select sum(size) from fs where type = 0 and fs.database_id = db.database_id) [                          DataFileSizeMB],(select sum(size) from fs where type = 1 and fs.database_id = db.database_id) [                          LogFileSizeMB] from sys.databases db\" -Y 20 | findstr /V (  &&" +
      "echo #^<tag:log_info^> && sqlcmd -Q \"set nocount on;dbcc sqlperf(logspace)\" -Y 30 | findstr /V DBCC &&" +
      "echo #^<tag:disk_io_status^> && sqlcmd -Q \"set nocount on;select @@total_read [read disk count],@@total_write [write disk count],@@total_errors [write disk error count],getdate() [current time]\" -Y 30 &&" +
      "echo #^<tag:dblock_status^> && sqlcmd -Q \"exec sp_lock\" &&" +
      "echo #^<tag:active_user_info^> && sqlcmd -Q \"exec sp_who2 'active'\" -Y 8 | findstr /V ( &&" +
      "chcp 437 > nul && echo #^<tag:user_login_info^> && sqlcmd -Q \"exec sp_helplogins\" -Y 27 | findstr /V ( | findstr /V ( &&" +
      "echo #^<tag:user_role_info^> && sqlcmd -Q \"exec sp_helpsrvrolemember\" -Y 25 | findstr /V (";
    }

    if( s_appliance_type.equals("oracle") )
    {
      s_awr =
      "echo 'SET ECHO OFF' > /tmp/.creawr.sql;" +
      "echo 'SET VERI OFF' >> /tmp/.creawr.sql;" +
      "echo 'SET FEEDBACK OFF' >> /tmp/.creawr.sql;" +
      "echo 'SET TERMOUT ON' >> /tmp/.creawr.sql;" +
      "echo 'SET HEADING OFF' >> /tmp/.creawr.sql;" +
      "echo 'SET PAGESIZE 50000' >> /tmp/.creawr.sql;" +

      "echo 'VARIABLE dbid NUMBER' >> /tmp/.creawr.sql;" +
      "echo 'VARIABLE inst_num NUMBER' >> /tmp/.creawr.sql;" +
      "echo 'VARIABLE bid NUMBER' >> /tmp/.creawr.sql;" +
      "echo 'VARIABLE eid NUMBER' >> /tmp/.creawr.sql;" +
      "echo 'BEGIN' >> /tmp/.creawr.sql;" +
      //"echo \"SELECT MIN (snap_id) INTO :bid FROM dba_hist_snapshot WHERE TO_CHAR (end_interval_time, 'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /tmp/.creawr.sql;" +
      //"echo \"SELECT MAX (snap_id) INTO :eid FROM dba_hist_snapshot WHERE TO_CHAR (begin_interval_time,'yyyymmdd') = TO_CHAR (SYSDATE-1, 'yyyymmdd');\" >> /tmp/.creawr.sql;" +
      "echo \"select max(snap_id)e into :eid from (select snap_id from dba_hist_snapshot order by 1 desc ) where rownum < 5;\" >> /tmp/.creawr.sql;" +
      "echo \"select min(snap_id)b into :bid from (select snap_id from dba_hist_snapshot order by 1 desc ) where rownum < 5;\" >> /tmp/.creawr.sql;" +
      //"echo \"select '170'e into :eid from dba_hist_snapshot where rownum < 2;\" >> /tmp/.creawr.sql;" +
      //"echo \"select '169'b into :bid from dba_hist_snapshot where rownum < 2;\" >> /tmp/.creawr.sql;" +
      "echo 'SELECT dbid INTO :dbid FROM v$database;' >> /tmp/.creawr.sql;" +
      "echo 'SELECT instance_number INTO :inst_num FROM v$instance;' >> /tmp/.creawr.sql;" +
      "echo 'END;' >> /tmp/.creawr.sql;" +
      "echo '/' >> /tmp/.creawr.sql;" +
      "echo \"SPOOL /tmp/.awr.txt\" >> /tmp/.creawr.sql;" +
      "echo 'SELECT output FROM TABLE (DBMS_WORKLOAD_REPOSITORY.awr_report_text(:dbid,:inst_num,:bid,:eid));' >> /tmp/.creawr.sql;" +
      "echo \"SPOOL OFF\" >> /tmp/.creawr.sql;" +

      "echo 'exit' >> /tmp/.creawr.sql;" +
      "chmod 777 /tmp/.creawr.sql;su - oracle -c \"export ORACLE_SID=" + s_insname + ";sqlplus -S / as sysdba @/tmp/.creawr.sql > /dev/null 2>&1\";" +

      s_awr_top_event +

      "echo \"echo '#<tag:pga_info>' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"echo ' ' >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +
      "echo \"b_num=\\$(cat /tmp/.awr.txt  | grep -in 'PGA Aggr Summary' | awk '{print \\$1}' | cut -d ':' -f 1)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"e_num=\\$(echo \\${b_num}+24 | bc)\" >> /tmp/.awr_statistics.sh;" +
      "echo \"cat /tmp/.awr.txt | sed -n \"\\${b_num},\\${e_num}p\" >> /tmp/.awr_statistics.log\" >> /tmp/.awr_statistics.sh;" +

      s_awr_top_sql +

      s_awr_performance +

      //"chmod +x /tmp/.awr_statistics.sh;sh /tmp/.awr_statistics.sh;cat /tmp/.awr_statistics.log | awk NF | sed 's/Top 10 Foreground/Top 5 Foreground/g';rm /tmp/.awr_statistics.sh;rm /tmp/.awr_statistics.log;rm /tmp/.awr.txt;rm /tmp/.creawr.sql;";
      "chmod +x /tmp/.awr_statistics.sh;bash /tmp/.awr_statistics.sh;cat /tmp/.awr_statistics.log | grep -v '                                                                               ' | sed 's/Top 10 Foreground/Top 5 Foreground/g';";

    }
    else if (s_appliance_type.equals("sqlserver"))
    {
      s_awr = "";
    }

    //System.out.println(s_oscheck + s_ins_check + s_db_check + s_awr);
    //return s_ins_check;
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
    if( re == null )
    {
      System.out.println("no value return from f_rmt_shell");
    }
    return re;
  }
}
