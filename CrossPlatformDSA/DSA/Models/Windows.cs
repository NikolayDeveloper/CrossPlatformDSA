//using CrossPlatformDSA.DSA.Interfaces;
//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Security.Cryptography.X509Certificates;
//using System.Threading.Tasks;

//namespace CrossPlatformDSA.DSA.Models.v2
//{
//    public class ECPServiceWin : IECPService
//    {
//        private UserCertInfo UserCertInfo { get; set; }
//        private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
//        public KalkanCryptCOMLib.KalkanCryptCOM _kalkan;
//        private int kalkanFlag;
//        private string outData, outVerifyInfo, outCert, errStr, outInfo;
//        uint err;
//        long outDateTime;
//        DateTime currentLocalTime = DateTime.Now;
//        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем

//        public ECPServiceWin()
//        {
//            _kalkan = new KalkanCryptCOMLib.KalkanCryptCOM();
//            _kalkan.Init();
//        }
//        public bool VerifyData(byte[] cms, UserCertInfo userCertInfo)
//        {
//            string errorCode;
//            //userCertInfo = new UserCertInfo();
//            string str;
//            bool res = false;
//            string base64StrCMS;
//            base64StrCMS = Convert.ToBase64String(cms);
//            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
//                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
//                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
//                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
//            // используем этот метод первым, чтобы вытащить сертификат
//            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
//            _kalkan.GetLastErrorString(out errStr, out err);
//            userCertInfo.ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, "проверка успешная без флага KC_NOCHECKCERTTIME");
//            errorCode = err.ConvertToHexErrorUint();
//            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
//            //Для игнорирования данной ошибки следует добавить флаг: kalkanFlags += KC_NOCHECKCERTTIME
//            if (errorCode == "0x08F00042")
//            {
//                kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
//                _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
//                _kalkan.GetLastErrorString(out errStr, out err);
//                userCertInfo.WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, null);
//            }



//            _kalkan.cert



//            if (err == 0)
//            {
//                userCertInfo.CMSvalidateMessage = err.SpecificCodeError(errStr, "Цифровая подпись прошла проверку");

//                try
//                {
//                    //получаем сведенья о сертификате вклячая отметку времени на момент подписания файла
//                    // GetUserCertificate(outCert, base64StrCMS, userCertInfo);
//                    // записываем в файл подписанные данные
//                    byte[] bytesFromBase64 = Convert.FromBase64String(outData);
//                    System.IO.File.WriteAllBytes(Path.Combine(Environment.CurrentDirectory, "sometext.txt"), bytesFromBase64);

//                    /////////////////////////////////////////////////

//                    // userCertInfo =  Shared.GetUserInfo(this, outCert, userCertInfo.UserInfoList);




//                }
//                catch (Exception ex)
//                {
//                    userCertInfo.ExtraInfo = ex.Message;
//                }
//                try
//                {
//                    // Проверка сертификата на отозванность на основе удостоверяющего центра OCSP
//                    _kalkan.X509ValidateCertificate(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP, OCSP_PATH, currentLocalTime, out outInfo);
//                    _kalkan.GetLastErrorString(out errStr, out err);
//                    errorCode = err.ConvertToHexErrorUint();
//                    if (err != 0)
//                    {
//                        userCertInfo.validCertificateMessage_ocsp = err.SpecificCodeError(errStr, null);
//                    }
//                    else if (err == 0)
//                    {
//                        userCertInfo.validCertificateMessage_ocsp = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                    }

//                    // Проверка сертификата на отозванность на основе скачаного файла crl в котором находится список отозванных сертификатов из pki.gov.kz 
//                    // Срок годности crl файла 1 день. Если мы хотим пользоваться crl нам нужно каждый день скачивать из https://pki.gov.kz/ новый crl файл, иначе он будет считаться истекшим
//                    // ошибка будет такого рода crl expired
//                    string crlPathRSA = Path.Combine(Environment.CurrentDirectory, "nca_rsa.crl");
//                    string crlPathGOST = Path.Combine(Environment.CurrentDirectory, "nca_gost.crl");
//                    // на основе алгоритма шифрование выберем соответствующий crl файл
//                    if (userCertInfo.SignatureAlg.Contains("RSA"))
//                    {
//                        _kalkan.X509ValidateCertificate(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathRSA, currentLocalTime, out outInfo);
//                        _kalkan.GetLastErrorString(out errStr, out err);
//                        if (err != 0)
//                        {
//                            userCertInfo.validCertificateMessage_crl = err.SpecificCodeError(errStr, null);
//                        }
//                        else
//                        {
//                            userCertInfo.validCertificateMessage_crl = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                        }

//                        ////////////////////////////////////////////////////////////
//                        Shared.ValidateSertificate_OCSP(this, outCert);
//                    }
//                    else if (userCertInfo.SignatureAlg.Contains("GOST"))
//                    {
//                        _kalkan.X509ValidateCertificate(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathGOST, currentLocalTime, out outInfo);
//                        _kalkan.GetLastErrorString(out errStr, out err);
//                        if (err != 0)
//                        {
//                            userCertInfo.validCertificateMessage_crl = err.SpecificCodeError(errStr, null);
//                        }
//                        else
//                        {
//                            userCertInfo.validCertificateMessage_crl = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                        }
//                    }
//                    else
//                    {
//                        throw new Exception($"В {userCertInfo.SignatureAlg} нет метода шифрования как GOST or RSA");
//                    }

//                    res = true;
//                }
//                catch (Exception ex)
//                {

//                    userCertInfo.ExtraInfo = ex.Message + ": errStr: " + errStr;
//                }
//            }
//            else
//            {
//                userCertInfo.CMSvalidateMessage = err.SpecificCodeError(errStr, null);
//            }
//            return res;
//        }
//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="cert"></param>
//        /// <param name="base64StrCMS"></param>
//        /// <param name="userCertInfo"></param>


//        //public void GetUserCertificate(string cert, string base64StrCMS,  UserCertInfo userCertInfo)
//        //{
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME, out userCertInfo.nameAndSurname);

//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME, out userCertInfo.middleName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SURNAME, out userCertInfo.surname);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SERIALNUMBER, out userCertInfo.IIN);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_EMAIL, out userCertInfo.email);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTBEFORE, out userCertInfo.notBefore);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTAFTER, out userCertInfo.notAfter);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN, out userCertInfo.serialNumberCert);

//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COUNTRYNAME, out userCertInfo.issuerCountryName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_SOPN, out userCertInfo.issuerSopn);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_LOCALITYNAME, out userCertInfo.issuerLocalityName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORG_NAME, out userCertInfo.issuerOrgName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORGUNIT_NAME, out userCertInfo.issuerOrgUnitName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COMMONNAME, out userCertInfo.issuerCommonName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COUNTRYNAME, out userCertInfo.subjectCountryName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SOPN, out userCertInfo.subjectSopn);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_LOCALITYNAME, out userCertInfo.subjectLocalityName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORG_NAME, out userCertInfo.subjectOrgName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORGUNIT_NAME, out userCertInfo.subjectOrgUnitName);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_BC, out userCertInfo.subjectBc);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DC, out userCertInfo.subjectDc);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_KEY_USAGE, out userCertInfo.keyUsage);

//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_EXT_KEY_USAGE, out userCertInfo.extKeyUsage);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_AUTH_KEY_ID, out userCertInfo.authKeyId);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJ_KEY_ID, out userCertInfo.subjKeyId);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN, out userCertInfo.certSn);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_DN, out userCertInfo.issuerDn);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DN, out userCertInfo.subjectDn);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out userCertInfo.signatureAlg);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_PUBKEY, out userCertInfo.pubkey);
//        //    _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_POLICIES_ID, out userCertInfo.policiesId);

//        //    //_kalkan.TSAGetTimeFromSig(base64StrCMS, kalkanFlag, 0, out outDateTime);
//        //    //_kalkan.GetLastErrorString(out errStr, out err);
//        //    //if (err == 0)
//        //    //{
//        //    //    userCertInfo.signTime = dateTime.AddSeconds(outDateTime).ToLocalTime();
//        //    //    userCertInfo.TSP_exists = new KeyValuePair<string, bool>("Успешно",true);
//        //    //}
//        //    //else
//        //    //{
//        //    //    userCertInfo.TSP_exists = new KeyValuePair<string, bool>("Не успешно", false);
//        //    //}
//        //}


//        //public KeyValuePair<string,bool> ValidateSertificate(object ECP, string cert,int kalkanFlag,string OCSP_or_CRL_Path)
//        //{
//        //    ECPServiceWin windowsECP = ECP as ECPServiceWin;
//        //    ECPServiceLinux linuxECP = ECP as ECPServiceLinux;

//        //    if(windowsECP != null)
//        //    {

//        //    }
//        //    else if(linuxECP != null)
//        //    {

//        //    }

//        //    KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
//        //    if(OCSP_or_CRL_Path.Contains("nca_rsa.crl"))
//        //    {

//        //    }
//        //    else if (OCSP_or_CRL_Path.Contains("nca_gost.crl"))
//        //    {

//        //    }
//        //    else if (OCSP_or_CRL_Path.Contains(OCSP_PATH))
//        //    {

//        //    }
//        //    else
//        //    {

//        //    }
//        //    return keyValue;
//        //}
//        public byte[] GetFile(byte[] cms)
//        {
//            throw new NotImplementedException();
//        }

//        public UserCertInfo GetAllInfo(byte[] cms)
//        {
//            UserCertInfo userCertInfo = new UserCertInfo();
//            try
//            {
//                userCertInfo = Shared.GetUserInfo(this, outCert, userCertInfo.UserInfoList);
//            }
//            catch (Exception ex)
//            {

//                throw ex;
//            }

//            return userCertInfo;
//        }

//        public UserCertInfo GetInfo(byte[] cms)
//        {
//            throw new NotImplementedException();
//        }
//        //private long GetTimeSignuture(byte[] cms)
//        //{
//        //   int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
//        //             (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
//        //             (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
//        //             (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
//        //   string base64StrCms = Convert.ToBase64String(cms);

//        //    _kalkan.TSAGetTimeFromSig(base64StrCms, kalkanFlag, 0, out outDateTime);
//        //    _kalkan.GetLastErrorString(out errStr, out err);
//        //    if (err == 0)
//        //    {
//        //        return outDateTime;
//        //    }
//        //    else
//        //    {
//        //        throw new Exception($"err: {err.ToString()} and discription errStr: {errStr}");
//        //    }
//        //}
//    }
//}
