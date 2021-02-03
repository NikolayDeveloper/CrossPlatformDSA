//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Reflection;
//using System.Runtime.InteropServices;
//using System.Text;
//using System.Threading.Tasks;

//namespace CrossPlatformDSA.DSA.Models
//{
//    public static class Shared
//    {
//        private static string OCSP_PATH = "http://ocsp.pki.gov.kz/";
//        private const int LENGTH_1 = 1000;
//        private const int LENGTH_2 = 64768;

//        public static KeyValuePair<string,bool> GetUserCert(object ECP,byte[] cms,out string outCertWin,out byte[] outCertLinux)
//        {
//            bool res = false;
//            outCertWin = "";
//            outCertLinux = new byte[LENGTH_2];
//            string errStr = "";
//            uint err;
//            KeyValuePair<string, bool> keyValue;
//            ECPServiceWin windowsECP = ECP as ECPServiceWin;
//            ECPServiceLinux linuxECP = ECP as ECPServiceLinux;
//            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
//                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
//                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
//                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
//            if (windowsECP != null)
//            {
//                windowsECP._kalkan.GetCertFromCMS(Encoding.UTF8.GetString(cms), kalkanFlag, 1, out outCertWin);
//                windowsECP._kalkan.GetLastErrorString(out errStr, out err);
//                if (err != 0)
//                {
//                    keyValue = err.SpecificCodeError(errStr, null);
//                }
//                else if (err == 0)
//                {
//                    keyValue = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                }
//            }
//            else if (linuxECP != null)
//            {

//            }
//            else
//            {
//                throw new Exception($"Ошибка привидения типов");
//            }
//            return res;
//        }
//            public static bool VerifyCMSData(byte[] cms, UserCertInfo userCertInfo)
//        {
//            bool res = false;
//            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
//            {
//                res = VerifyCMSDataWindows(cms, userCertInfo);
//            }
//            else
//            {
//               res = VerifyCMSDataLinux(cms, userCertInfo);
//            }
//            return res;
//        }
//        private static bool VerifyCMSDataLinux(byte[] cms, UserCertInfo userCertInfo)
//        {


//            return true;
//        }
//        private static bool VerifyCMSDataWindows(byte[] cms, UserCertInfo userCertInfo)
//        {


//            return true;
//        }
//        /// <summary>
//        /// Проверка сертификата на отозванность с помощью OCSP
//        /// </summary>
//        /// <param name="ECP"></param>
//        /// <param name="cert"></param>
//        /// <returns></returns>
//        public static KeyValuePair<string, bool> ValidateSertificate_OCSP(object ECP, string cert)
//        {
//            string errStr = "";
//            uint err;
//            ulong codeError;
//            int bufSize;
//            string outInfo;
//            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
//            ECPServiceWin windowsECP = ECP as ECPServiceWin;
//            ECPServiceLinux linuxECP = ECP as ECPServiceLinux;
//            DateTime currentLocalTime = DateTime.Now;
//            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
//            if (windowsECP != null)
//            {
//                windowsECP._kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP, OCSP_PATH, currentLocalTime, out outInfo);
//                windowsECP._kalkan.GetLastErrorString(out errStr, out err);
//                if (err != 0)
//                {
//                    keyValue = err.SpecificCodeError(errStr, null);
//                }
//                else if (err == 0)
//                {
//                    keyValue = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                }
//            }
//            else if (linuxECP != null)
//            {

//            }
//            else
//            {
//                throw new Exception($"Ошибка привидения типов");
//            }

//            return keyValue;
//        }
//        /// <summary>
//        /// Проверка сертификата на отозванность с помощью CRL
//        /// </summary>
//        /// <param name="ECP"></param>
//        /// <param name="cert"></param>
//        /// <returns></returns>
//        public static KeyValuePair<string, bool> ValidateSertificate_CRl(object ECP, string cert)
//        {
//            string errStr = new string('d', LENGTH_1);
//            uint err;
//            ulong codeError;
//            int bufSize;
//            string outInfo = new string('d', LENGTH_2);
//            string alg = new string('d',LENGTH_1);
//            int outDataLength= LENGTH_1;
//            int outInfoLength = LENGTH_1;
//            string crlPathRSA = Path.Combine(Environment.CurrentDirectory, "nca_rsa.crl");
//            string crlPathGOST = Path.Combine(Environment.CurrentDirectory, "nca_gost.crl");
//            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
//            ECPServiceWin windowsECP = ECP as ECPServiceWin;
//            ECPServiceLinux linuxECP = ECP as ECPServiceLinux;
//            DateTime currentLocalTime = DateTime.Now;
//            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
//            try
//            {
//                // Windows
//                if (windowsECP != null)
//                {
//                    // узнаем алгоритм шифрования
//                    windowsECP._kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out alg);
//                    windowsECP._kalkan.GetLastErrorString(out errStr,out err);
//                    if(err != 0)
//                    {
//                        throw new Exception($"err: {err.ToString()} and discription errStr: {errStr}");
//                    }
//                    // на основе алгоритма шифрование выберем соответствующий crl файл
//                    if (alg.Contains("RSA"))
//                    {
//                        windowsECP._kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathRSA, currentLocalTime, out outInfo);
//                        windowsECP._kalkan.GetLastErrorString(out errStr, out err);
//                        if (err != 0)
//                        {
//                            keyValue = err.SpecificCodeError(errStr, null);
//                        }
//                        else if (err == 0)
//                        {
//                            keyValue = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                        }
//                    }
//                    else if(alg.Contains("GOST"))
//                    {
//                        windowsECP._kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathGOST, currentLocalTime, out outInfo);
//                        windowsECP._kalkan.GetLastErrorString(out errStr, out err);
//                        if (err != 0)
//                        {
//                            keyValue = err.SpecificCodeError(errStr, null);
//                        }
//                        else if (err == 0)
//                        {
//                            keyValue = err.SpecificCodeError(errStr, " удостоверяющий центр опознан");
//                        }
//                    }
//                    else
//                    {
//                        throw new Exception($"Такого алгоритма шифрования как {alg} не существует");
//                    }
//                }
//                // Linux
//                else if (linuxECP != null)
//                {
//                    // узнаем алгоритм шифрования
//                    codeError = ECPServiceLinux.X509CertificateGetInfo(ref Encoding.UTF8.GetBytes(cert)[0],cert.Length, 
//                                                            (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, 
//                                                            out Encoding.UTF8.GetBytes(alg)[0],ref outDataLength);
//                    if (codeError != 0)
//                    {
//                        bufSize = 1000;
//                        ECPServiceLinux.KC_GetLastErrorString(ref Encoding.UTF8.GetBytes(errStr)[0], ref bufSize);
//                        throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr}");
//                    }
//                    // на основе алгоритма шифрование выберем соответствующий crl файл
//                    if (alg.Contains("RSA"))
//                    {
//                        codeError = ECPServiceLinux.X509ValidateCertificate(ref Encoding.UTF8.GetBytes(cert)[0], cert.Length,
//                                                                            (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL,
//                                                                           ref Encoding.UTF8.GetBytes(crlPathRSA)[0], currentLocalUnixTime, 
//                                                                           out Encoding.UTF8.GetBytes(outInfo)[0], out outInfoLength);
//                        if (codeError != 0)
//                        {
//                            bufSize = 1000;
//                            ECPServiceLinux.KC_GetLastErrorString(ref Encoding.UTF8.GetBytes(errStr)[0], ref bufSize);
//                            keyValue = new KeyValuePair<string, bool>(errStr, false);
//                            //throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr}");
//                        }
//                        else
//                        {
//                            keyValue = new KeyValuePair<string, bool>("удостоверяющий центр опознан", true);
//                        }
                        
                        
//                    }
//                    else if (alg.Contains("GOST"))
//                    {
//                        codeError = ECPServiceLinux.X509ValidateCertificate(ref Encoding.UTF8.GetBytes(cert)[0], cert.Length,
//                                                                            (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL,
//                                                                           ref Encoding.UTF8.GetBytes(crlPathGOST)[0], currentLocalUnixTime,
//                                                                           out Encoding.UTF8.GetBytes(outInfo)[0], out outInfoLength);
//                        if (codeError != 0)
//                        {
//                            bufSize = 1000;
//                            ECPServiceLinux.KC_GetLastErrorString(ref Encoding.UTF8.GetBytes(errStr)[0], ref bufSize);
//                            keyValue = new KeyValuePair<string, bool>(errStr, false);
//                            //throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr}");
//                        }
//                        else
//                        {
//                            keyValue = new KeyValuePair<string, bool>("удостоверяющий центр опознан", true);
//                        }
//                    }
//                    else
//                    {
//                        throw new Exception($"Такого алгоритма шифрования как {alg} не существует");
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                throw ex;
//            }
            
//            return keyValue;
//        }
//        /// <summary>
//        /// Получение отметки времени подписи
//        /// </summary>
//        /// <param name="ECP"></param>
//        /// <param name="cms"></param>
//        /// <returns></returns>
//        public static DateTime GetTimeSignuture(object ECP,string cms)
//        {
//            ECPServiceWin windowsECP = ECP as ECPServiceWin;
//            ECPServiceLinux linuxECP = ECP as ECPServiceLinux;
//            long outDateTime = 0;
//            string errStr="";
//            uint err;
//            ulong codeError;
//            int bufSize;
//            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
//                     (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
//                     (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
//                     (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
//            if (windowsECP != null)
//            {
//                windowsECP._kalkan.TSAGetTimeFromSig(cms, kalkanFlag, 0, out outDateTime);
//                windowsECP._kalkan.GetLastErrorString(out errStr, out err);
//                if (err == 0)
//                {
//                    return new DateTime().AddSeconds(outDateTime).ToLocalTime();
//                }
//                else
//                {
//                    throw new Exception($"err: {err.ToString()} and discription errStr: {errStr}");
//                }
//            }
//            else if (linuxECP != null)
//            {
//                codeError = ECPServiceLinux.KC_GetTimeFromSig(ref Encoding.UTF8.GetBytes(cms)[0], cms.Length, kalkanFlag, 0, out outDateTime);
//                if (codeError != 0)
//                {
//                    bufSize = 1000;
//                    ECPServiceLinux.KC_GetLastErrorString(ref Encoding.UTF8.GetBytes(errStr)[0], ref bufSize);
                    
//                    throw new Exception($"err: {codeError.ConvertToHexError()} and discription errStr: {errStr}");
//                }
              
//            }
//            else
//            {
//                throw new Exception($"Ошибка привидения типов");
//            }

//            return new DateTime().AddSeconds(outDateTime).ToLocalTime();
//        }

//        /// <summary>
//        /// Получение информации о пользователе и о сертификате
//        /// </summary>
//        /// <param name="ECP"></param>
//        /// <param name="cert"></param>
//        /// <param name="userInfoList"></param>
//        /// <returns></returns>
//        public static UserCertInfo GetUserInfo(object ECP, string cert, Dictionary<string,int> userInfoList)
//        {
//            UserCertInfo userCertInfo = new UserCertInfo();
//            Type type = typeof(UserCertInfo);
//            string res;
//            ECPServiceWin windowsECP = ECP as ECPServiceWin;
//            ECPServiceLinux linuxECP = ECP as ECPServiceLinux;
//            try
//            {
//                foreach (var info in userInfoList)
//                {
//                    windowsECP._kalkan.X509CertificateGetInfo(cert, info.Value, out res);
//                    PropertyInfo property = type.GetProperty(info.Key);
//                    property.SetValue(userCertInfo, res);
//                }
//            }
//            catch (Exception ex)
//            {
//                throw ex;
//            }
            
//            return userCertInfo;
//        }
//    }
//}
