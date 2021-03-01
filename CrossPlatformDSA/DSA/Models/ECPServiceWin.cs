using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using WTO.Classes.Infrastructure.Services.Logger.Abstract;

namespace CrossPlatformDSA.DSA.Models
{
    public class ECPServiceWin : IECPService
    {
        private UserCertInfo UserCertInfo { get; set; }
        private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
        private IAppLog _appLog;
        public KalkanCryptCOMLib.KalkanCryptCOM _kalkan;
        public string CENTER_DETERMINED_MESSAGE= "Удостоверяющий центр опознан";
        //private int kalkanFlag;
        //private string outData, outVerifyInfo, outCert, errStr, outInfo;
        //uint err;
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем

        public ECPServiceWin(IAppLog appLog)
        {
            _appLog = appLog;
            _kalkan = new KalkanCryptCOMLib.KalkanCryptCOM();
            _kalkan.Init();
        }

        #region public methods
        /// <summary>
        /// Проверка cms подписи на целостность, отозванность с помощью OCSP и CRL
        /// </summary>
        /// <param name="cms"></param>
        /// <param name="userCertInfo"></param>
        /// <returns></returns>
        public bool VerifyData(byte[] cms, UserCertInfo userCertInfo)
        {
           // Console.WriteLine();
            _appLog.WriteLog("начало метода VerifyData on Windows");
            string ncaLayerCms = "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";
            string ncaLayerFileCms = "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";

            string errorCode;
           // userCertInfo = new UserCertInfo();
            string str, errStr, outData, outVerifyInfo, outCert;
            uint err;
            bool res = false;
            string base64StrCMS;
            base64StrCMS = Convert.ToBase64String(cms);
            byte[] count = Encoding.UTF8.GetBytes(base64StrCMS);
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                    (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                  // (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            // Проверяем отметку времени
            userCertInfo.TSP_exists = ValidateTimeSignuture(cms);
            // вытаскиваем сертификат для дальнейшей работы
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            userCertInfo.ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, "проверка успешная без флага KC_NOCHECKCERTTIME");
            errorCode = err.ConvertToHexErrorUint();
            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
            //Для игнорирования данной ошибки следует добавить флаг: kalkanFlags += KC_NOCHECKCERTTIME
            if (errorCode == "0x08F00042")
            {
                kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
                _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
                _kalkan.GetLastErrorString(out errStr, out err);
                userCertInfo.WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, null);
            }
            if (err == 0)
            {
                userCertInfo.CMSvalidateMessage = err.SpecificCodeError(errStr, "Цифровая подпись прошла проверку");

                try
                {
                    // записываем в файл подписанные данные
                    SaveExtractedDataFromCMSToFile(outData);
                }
                catch (Exception ex)
                {
                    userCertInfo.ExtraInfo = ex.Message;
                }
                try
                {
                    // Проверка сертификата на отозванность на основе удостоверяющего центра OCSP
                    userCertInfo.validCertificateMessage_ocsp = ValidateSertificate_OCSP(outCert);
                    // Проверка сертификата на отозванность на основе скачаного файла crl в котором находится список отозванных сертификатов из pki.gov.kz 
                    // Срок годности crl файла 1 день. Если мы хотим пользоваться crl нам нужно каждый день скачивать из https://pki.gov.kz/ новый crl файл, иначе он будет считаться истекшим
                    // ошибка будет такого рода crl expired
                    userCertInfo.validCertificateMessage_crl = ValidateSertificate_CRl(outCert);
                    res = true;
                }
                catch (Exception ex)
                {
                    userCertInfo.ExtraInfo = ex.Message + ": errStr: " + errStr;
                }
            }
            else
            {
                userCertInfo.CMSvalidateMessage = err.SpecificCodeError(errStr, null);
            }
            return res;
        }
        
        /// <summary>
        /// Получение информации о сертификате
        /// </summary>
        /// <param name="cms"></param>
        /// <returns></returns>
        public UserCertInfo GetInfo(byte[] cms)
        {
            string outCert = "";
           // UserCertInfo userCertInfo = new UserCertInfo();
            UserCertInfo userCertInfo = null ;
            Dictionary<string, int> userInfoList = new UserCertInfo().UserInfoList();
            try
            {
                outCert = GetCertFromCms(cms);
                userCertInfo = GetUserInfo(outCert, userInfoList);
                userCertInfo.SignTime = GetTimeSignuture(cms);
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return userCertInfo;
        }

        #endregion

        #region private methods
        private KeyValuePair<string, bool> ValidateSertificate_OCSP(string cert)
        {
            string errStr = "";
            uint err;
            string outInfo;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            DateTime currentLocalTime = DateTime.Now;
            _kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP, OCSP_PATH, currentLocalTime, out outInfo);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
                keyValue = err.SpecificCodeError(errStr, CENTER_DETERMINED_MESSAGE);
            }
            else
            {
                keyValue = err.SpecificCodeError(errStr, null);
            }
            return keyValue;
        }

        private KeyValuePair<string, bool> ValidateSertificate_CRl(string cert)
        {
            string alg="";
            string errStr = "";
            uint err;
            string outInfo;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            string crlPathRSA = Path.Combine(Environment.CurrentDirectory, "nca_rsa.crl");
            string crlPathGOST = Path.Combine(Environment.CurrentDirectory, "nca_gost.crl");
            DateTime currentLocalTime = DateTime.Now;
            // узнаем алгоритм шифрования
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out alg);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err != 0)
            {
                throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
            // на основе алгоритма шифрование выберем соответствующий crl файл
            if (alg.Contains("RSA"))
            {
                _kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathRSA, currentLocalTime, out outInfo);
                _kalkan.GetLastErrorString(out errStr, out err);
                if (err != 0)
                {
                    keyValue = err.SpecificCodeError(errStr, null);
                }
                else if (err == 0)
                {
                    keyValue = err.SpecificCodeError(errStr, CENTER_DETERMINED_MESSAGE);
                }
            }
            else if (alg.Contains("GOST"))
            {
                _kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathGOST, currentLocalTime, out outInfo);
                _kalkan.GetLastErrorString(out errStr, out err);
                if (err != 0)
                {
                    keyValue = err.SpecificCodeError(errStr, null);
                }
                else if (err == 0)
                {
                    keyValue = err.SpecificCodeError(errStr, CENTER_DETERMINED_MESSAGE);
                }
            }
            else
            {
                throw new Exception($"Такого алгоритма шифрования как {alg} не существует");
            }
            return keyValue;
        }

        private DateTime GetTimeSignuture(byte[] cms)
        {
            string errStr;
            uint err;
            long outDateTime;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            string base64StrCms = Convert.ToBase64String(cms);

            _kalkan.TSAGetTimeFromSig(base64StrCms, kalkanFlag, 0, out outDateTime);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
                return dateTime.AddSeconds(outDateTime).ToLocalTime();
            }
            else
            {
                return new DateTime();
                //throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
        }

        private KeyValuePair<string, bool> ValidateTimeSignuture(byte[] cms)
        {
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>(null, false);
            string errStr;
            uint err;
            long outDateTime;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            string base64StrCms = Convert.ToBase64String(cms);

            _kalkan.TSAGetTimeFromSig(base64StrCms, kalkanFlag, 0, out outDateTime);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
               keyValue = new KeyValuePair<string, bool>("Успешно", true);
               return keyValue;
            }
            else
            {
                keyValue = new KeyValuePair<string, bool>("Не успешно", false);
                return keyValue;
                //throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
        }

        private string GetCertFromCms(byte[] cms)
        {
            string outCert, errStr;
            uint err;
           int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            string base64StrCMS = Convert.ToBase64String(cms);
            _kalkan.GetCertFromCMS(base64StrCMS, kalkanFlag, 1, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
                return outCert;
            }
            else
            {
                throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
        }

        private UserCertInfo GetUserInfo(string cert, Dictionary<string, int> userInfoList)
        {
            UserCertInfo userCertInfo = new UserCertInfo();
            Type type = typeof(UserCertInfo);
            string res;
            try
            {
                foreach (var info in userInfoList)
                {
                    _kalkan.X509CertificateGetInfo(cert, info.Value, out res);
                    PropertyInfo property = type.GetProperty(info.Key);
                    property.SetValue(userCertInfo, res);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return userCertInfo;
        }

        private bool SaveExtractedDataFromCMSToFile(string data)
        {
            bool res = false;
            try
            {
                byte[] bytesFromBase64 = Convert.FromBase64String(data);
                System.IO.File.WriteAllBytes(Path.Combine(Environment.CurrentDirectory, "sometext.txt"), bytesFromBase64);
                res = true;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return res;
        }

        #endregion





        public byte[] GetFile(byte[] cms)
        {
            throw new NotImplementedException();
        }
    }
}
