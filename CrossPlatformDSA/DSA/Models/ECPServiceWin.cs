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
        //private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
        private string OCSP_PATH = "http://test.pki.gov.kz/ocsp/";


        
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
        /// Получение исходных подписанных данных из cms
        /// </summary>
        /// <param name="cms"></param>
        /// <returns></returns>
        public byte[] GetFile(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetFile on Windows");
            string errorCode;
            string str, errStr, outData, outVerifyInfo, outCert;
            uint err;
            bool res = false;
            string base64StrCMS;
            base64StrCMS = Convert.ToBase64String(cms);
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                    (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
            // вытаскиваем сертификат для дальнейшей работы
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            errorCode = err.ConvertToHexErrorUint();
            _appLog.WriteLog("VerifyData Output::: " +
                "\n||kalkanFlag - " + kalkanFlag.ToString() +
                "\n||err - " + errorCode +
                "\n||errStr - " + errStr +
                "\n||outData - " + outData +
                "\n|| outVerifyInfo - " + outVerifyInfo +
                "\n|| outCert count - " + outCert.Length);
            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
            //Для игнорирования данной ошибки следует добавить флаг: kalkanFlags += KC_NOCHECKCERTTIME
            if (errorCode == "0x08F00042")
            {
                kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
                _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
                _kalkan.GetLastErrorString(out errStr, out err);
                _appLog.WriteLog("VerifyData Output::: " +
                "\n||kalkanFlag - " + kalkanFlag.ToString() +
                "\n||err - " + errorCode +
                "\n||errStr - " + errStr +
                "\n||outData - " + outData +
                "\n|| outVerifyInfo - " + outVerifyInfo +
                "\n|| outCert count - " + outCert.Length);
            }
            if (!string.IsNullOrEmpty(outData))
            {
                byte[] result = Convert.FromBase64String(outData);
                _appLog.WriteLog("VerifyData return from method::: ||countBytes - " + result.Length);
                _appLog.WriteLog("Завершение метода GetFile on Windows");
                return result;
            }
            _appLog.WriteLog("Завершение метода GetFile on Windows");
            return null;
        }
        /// <summary>
        /// Проверка cms подписи на целостность, отозванность с помощью OCSP и CRL
        /// </summary>
        /// <param name="cms"></param>
        /// <param name="userCertInfo"></param>
        /// <returns></returns>
        public bool VerifyData(byte[] cms, UserCertInfo userCertInfo)
        {
            _appLog.WriteLog("Начало метода VerifyData on Windows");
            string errorCode;
           // userCertInfo = new UserCertInfo();
            string str, errStr, outData, outVerifyInfo, outCert;
            uint err;
            bool res = false;
            string base64StrCMS;
            base64StrCMS = Convert.ToBase64String(cms);
           // byte[] count = Encoding.UTF8.GetBytes(base64StrCMS);
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                    (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
            // Проверяем отметку времени
            userCertInfo.TSP_exists = ValidateTimeSignuture(cms);
            if (!userCertInfo.TSP_exists.Value)
            {
                return false;
            }
            // вытаскиваем сертификат для дальнейшей работы
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            userCertInfo.ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, "проверка успешная без флага KC_NOCHECKCERTTIME");
            errorCode = err.ConvertToHexErrorUint();
            _appLog.WriteLog("VerifyData Output::: " +
                 "\n||kalkanFlag - " + kalkanFlag.ToString() +
                 "\n||err - " + errorCode +
                 "\n||errStr - " + errStr +
                 "\n||outData - " + outData +
                 "\n|| outVerifyInfo - " + outVerifyInfo +
                 "\n|| outCert count - " + outCert.Length);

            //Если при проверке подписи выходит ошибка -0x08F00042, то сертификат просрочен.
            //Для игнорирования данной ошибки следует добавить флаг: kalkanFlags += KC_NOCHECKCERTTIME
            //if (errorCode == "0x08F00042")
            //{
            //    kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
            //    _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            //    _kalkan.GetLastErrorString(out errStr, out err);
            //    userCertInfo.WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME = err.SpecificCodeError(errStr, null);
            //}
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
                    if (!string.IsNullOrEmpty(outCert))
                    {
                        // Проверка сертификата на отозванность на основе удостоверяющего центра OCSP
                        userCertInfo.validCertificateMessage_ocsp = ValidateSertificate_OCSP(outCert);
                        if (!userCertInfo.validCertificateMessage_ocsp.Value)
                        {
                            return false;
                        }
                        // Проверка сертификата на отозванность на основе скачаного файла crl в котором находится список отозванных сертификатов из pki.gov.kz 
                        // Срок годности crl файла 1 день. Если мы хотим пользоваться crl нам нужно каждый день скачивать из https://pki.gov.kz/ новый crl файл, иначе он будет считаться истекшим
                        // ошибка будет такого рода crl expired
                        userCertInfo.validCertificateMessage_crl = ValidateSertificate_CRl(outCert);
                        if (!userCertInfo.validCertificateMessage_crl.Value)
                        {
                            return false;
                        }
                        res = true;
                    }
                    else
                    {
                        throw new Exception("parametr outCert is empty");
                    }
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
            _appLog.WriteLog("Завершение метода VerifyData on Windows");
            return res;
        }
        
        /// <summary>
        /// Получение информации о сертификате
        /// </summary>
        /// <param name="cms"></param>
        /// <returns></returns>
        public UserCertInfo GetInfo(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetInfo on Windows");
            string outCert = "";
            UserCertInfo userCertInfo = null ;
            // на основе этого списка будет извлекаться инфо из сертификата
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
            _appLog.WriteLog("Завершение метода GetInfo on Windows");
            return userCertInfo;
        }

        #endregion

        #region private methods
        private KeyValuePair<string, bool> ValidateSertificate_OCSP(string cert)
        {
            _appLog.WriteLog("Начало метода ValidateSertificate_OCSP on Windows");
            string errStr = "";
            uint err;
            string outInfo;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            DateTime currentLocalTime = DateTime.Now;
            _kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP, OCSP_PATH, currentLocalTime, out outInfo);
            _kalkan.GetLastErrorString(out errStr, out err);
            _appLog.WriteLog("X509ValidateCertificate KC_USE_OCSP Output::: " + "||outInfo "+ outInfo + "||err - " + err.ConvertToHexErrorUint() + "||errStr - " + errStr);
            if (err == 0)
            {
                keyValue = err.SpecificCodeError(errStr, CENTER_DETERMINED_MESSAGE);
            }
            else
            {
                keyValue = err.SpecificCodeError(errStr, null);
            }
            _appLog.WriteLog("Завершение метода ValidateSertificate_OCSP on Windows");
            return keyValue;
        }

        private KeyValuePair<string, bool> ValidateSertificate_CRl(string cert)
        {
            _appLog.WriteLog("Начало метода ValidateSertificate_CRl on Windows");
            string alg="";
            string errStr = "";
            uint err;
            string outInfo;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            // string crlPathRSA = Path.Combine(Environment.CurrentDirectory, "nca_rsa.crl");
            // string crlPathGOST = Path.Combine(Environment.CurrentDirectory, "nca_gost.crl");
            string crlPathRSA = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "crlFiles", "nca_rsa.crl");
            string crlPathGOST = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "crlFiles", "nca_gost.crl");
            DateTime currentLocalTime = DateTime.Now;
            // узнаем алгоритм шифрования
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out alg);
            _kalkan.GetLastErrorString(out errStr, out err);
            _appLog.WriteLog("X509CertificateGetInfo Output::: " + "||alg " + alg + "||err - " + err.ConvertToHexErrorUint() + "||errStr - " + errStr);
            if (err != 0)
            {
                throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
            // на основе алгоритма шифрование выберем соответствующий crl файл
            if (alg.Contains("RSA"))
            {
                _kalkan.X509ValidateCertificate(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL, crlPathRSA, currentLocalTime, out outInfo);
                _kalkan.GetLastErrorString(out errStr, out err);
                _appLog.WriteLog("X509ValidateCertificate KC_USE_CRL Output::: " + "||outInfo " + outInfo + "||err - " + err.ConvertToHexErrorUint() + "||errStr - " + errStr);
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
                _appLog.WriteLog("X509ValidateCertificate KC_USE_CRL Output::: " + "||outInfo " + outInfo + "||err - " + err.ConvertToHexErrorUint() + "||errStr - " + errStr);
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
            _appLog.WriteLog("Завершение метода ValidateSertificate_CRl on Windows");
            return keyValue;
        }

        private DateTime GetTimeSignuture(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetTimeSignuture on Windows");
            string errStr;
            uint err;
            long outDateTime;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                      (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
            string base64StrCms = Convert.ToBase64String(cms);
            _kalkan.TSAGetTimeFromSig(base64StrCms, kalkanFlag, 0, out outDateTime);
            _kalkan.GetLastErrorString(out errStr, out err);
            _appLog.WriteLog("VerifyData Output::: " +
                "\n||kalkanFlag - " + kalkanFlag.ToString() +
                "\n||err - " + err.ConvertToHexErrorUint() +
                "\n||errStr - " + errStr +
                "\n||outDateTime - " + outDateTime);
            if (err == 0)
            {
                _appLog.WriteLog("Завершение метода GetTimeSignuture on Windows");
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
            _appLog.WriteLog("Начало метода ValidateTimeSignuture on Windows");
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
            _appLog.WriteLog("VerifyData Output::: " +
               "\n||kalkanFlag - " + kalkanFlag.ToString() +
               "\n||err - " + err.ConvertToHexErrorUint() +
               "\n||errStr - " + errStr +
               "\n||outDateTime - " + outDateTime);
            if (err == 0)
            {
               keyValue = new KeyValuePair<string, bool>("Успешно", true);
                _appLog.WriteLog("Завершение метода ValidateTimeSignuture on Windows");
                return keyValue;
            }
            else
            {
                keyValue = new KeyValuePair<string, bool>("Не успешно", false);
                _appLog.WriteLog("Завершение метода ValidateTimeSignuture on Windows");
                return keyValue;
                //throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
        }

        private string GetCertFromCms(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetCertFromCms on Windows");
            string outCert, errStr;
            uint err;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
            string base64StrCMS = Convert.ToBase64String(cms);
            _kalkan.GetCertFromCMS(base64StrCMS, kalkanFlag, 1, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);
            _appLog.WriteLog("VerifyData Output::: " +
              "\n||kalkanFlag - " + kalkanFlag.ToString() +
              "\n||err - " + err.ConvertToHexErrorUint() +
              "\n||errStr - " + errStr +
              "\n||outCert count - " + outCert.Length);
            if (err == 0)
            {
                _appLog.WriteLog("Завершение метода GetCertFromCms on Windows");
                return outCert;
            }
            else
            {
                throw new Exception($"err: {err.ConvertToHexErrorUint()} and discription errStr: {errStr}");
            }
        }

        private UserCertInfo GetUserInfo(string cert, Dictionary<string, int> userInfoList)
        {
            _appLog.WriteLog("Начало метода GetUserInfo on Windows");
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
            _appLog.WriteLog("Завершение метода GetUserInfo on Windows");
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
    }
}
