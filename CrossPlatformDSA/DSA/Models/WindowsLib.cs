using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class WindowsLib : ILibrary
    {
        KalkanCryptCOMLib.KalkanCryptCOM _kalkan;
        private int kalkanFlag;
        private string outData, outVerifyInfo, outCert, errStr;
        uint err;
        long outDateTime;
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем
      
        public WindowsLib()
        {
            _kalkan = new KalkanCryptCOMLib.KalkanCryptCOM();
            _kalkan.Init();
        }
        public bool VerifyData(byte[] data,out UserCertInfo userCertInfo)
        {
            userCertInfo = null;  
            bool res = false;
            string base64StrCMS;
            base64StrCMS = Convert.ToBase64String(data);
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            if(err==0)
            {
                res = true;
                try
                {
                    userCertInfo = GetUserCertificate(outCert, base64StrCMS);

                    byte[]bytesFromBase64 = Convert.FromBase64String(outData);
                    System.IO.File.WriteAllBytes(Path.Combine(Environment.CurrentDirectory,"sometext.txt"), bytesFromBase64);
                }
                catch (Exception ex)
                {
                    userCertInfo.extraInfo = ex.Message;
                }
               

            }
            return res;
        }
        public UserCertInfo GetUserCertificate(string cert,string base64StrCMS)
        {
            UserCertInfo userCertInfo = new UserCertInfo();
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME, out userCertInfo.nameAndSurname);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME, out userCertInfo.middleName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SURNAME, out userCertInfo.surname);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SERIALNUMBER, out userCertInfo.IIN);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_EMAIL, out userCertInfo.email);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTBEFORE, out userCertInfo.notBefore);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTAFTER, out userCertInfo.notAfter);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN, out userCertInfo.serialNumberCert);
            _kalkan.TSAGetTimeFromSig(base64StrCMS, kalkanFlag, 0, out outDateTime);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
                userCertInfo.signTime = dateTime.AddSeconds(outDateTime).ToLocalTime();
            }
            return userCertInfo;
        }
    }
}
