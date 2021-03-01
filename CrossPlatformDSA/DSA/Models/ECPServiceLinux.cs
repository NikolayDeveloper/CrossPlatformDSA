﻿using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using WTO.Classes.Infrastructure.Services.Logger.Abstract;

namespace CrossPlatformDSA.DSA.Models
{
    public class ECPServiceLinux : IECPService
    {
        private IAppLog _appLog;
        public ECPServiceLinux(IAppLog appLog)
        {
            _appLog = appLog;
            Init();
            KC_TSASetUrl($"http://tsp.pki.gov.kz:80");
        }
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем
        public string CENTER_DETERMINED_MESSAGE = "Удостоверяющий центр опознан";
        //private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
        private string OCSP_PATH = "http://test.pki.gov.kz/ocsp/";
        const string LIB_NAME = "kalkancryptwr-64";
        const int LENGTH = 64768;
        const int MINLENTH = 2000;
        int inCertID = 1;
        
        
        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong Init();

        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern void KC_TSASetUrl(string tsaurl);

        [DllImport(LIB_NAME, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong KC_GetLastErrorString(ref byte errorString, ref int bufSize);

        [DllImport(LIB_NAME, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong KC_GetLastError();

        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong VerifyData(ref byte alias, int flags, ref byte inData, int inDataLength, ref sbyte inoutSign, int inoutSignLength,
                                                out byte outData, out int outDataLen, out byte outVerifyInfo, out int outVerifyInfoLen,
                                                int inCertID, out byte outCert, out int outCertLength);
        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong X509CertificateGetInfo(ref byte inCert, int inCertLength, int propId, out byte outData, ref int outDataLength);
        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong KC_GetTimeFromSig(ref byte inData, int inDataLength, int flags, int inSigId, out long outDateTime);
        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong X509ValidateCertificate(ref byte inCert, int inCertLength, int oCSPType, ref byte ocspPath,long currentLocalUnixTime,out byte outInfo,out int outInfoLength);

        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong KC_GetCertFromCMS (ref byte inCMS, int inCMSLen, int inSignId, int flags, out byte outCert, out int outCertLength);

        public byte[] GetFile(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetFile on Linux");
            byte alias = 12;
            string outDataStr=null;
            string base64Str = Convert.ToBase64String(cms);
            byte[] base64Cms = Encoding.UTF8.GetBytes(base64Str);
            sbyte[] inoutSign = (sbyte[])((Array)base64Cms);
            ulong codeError;
            byte[] errStr = new byte[MINLENTH];
            byte[] outCert = new byte[LENGTH];
            byte[] outData = new byte[base64Cms.Length];
            byte[] outVerifyInfo = new byte[MINLENTH];
            int outCertLength = LENGTH;
            int outDataLen = outData.Length;
            int outVerifyInfoLen = MINLENTH;
            byte[] inData = new byte[1];
            bool res = false;
            int kalkanFlag; //= 2322;
            string codeErrorStr;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                 // (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            // вытаскиваем сертификат для дальнейшей работы
            codeError = VerifyData(ref alias, kalkanFlag, ref inData[0], inData.Length, ref inoutSign[0], inoutSign.Length,
                                    out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                    inCertID, out outCert[0], out outCertLength);
            codeError = KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("VerifyData Output::: " +
                "||kalkanFlag - " + kalkanFlag.ToString() +
                "||codeError - " + codeError.ConvertToHexError() +
                "||errStr - " +errStr.GetString() +
                "||outData - " + outData.GetString() +
                "||outVerifyInfo - " + outVerifyInfo.GetString() +
                "||count bytes outCert - " + outCert.Length);
            
            codeErrorStr = codeError.ConvertToHexError();
            if (codeErrorStr == "0x08F00042")
            {
                bufSize = MINLENTH;
                kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
                codeError = VerifyData(ref alias, kalkanFlag, ref inData[0], inData.Length, ref inoutSign[0], inoutSign.Length,
                                     out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                     inCertID, out outCert[0], out outCertLength);
                codeError = KC_GetLastErrorString(ref errStr[0], ref bufSize);
                _appLog.WriteLog("VerifyData Output::: " +
              "||kalkanFlag - " + kalkanFlag.ToString() +
              "||codeError - " + codeError.ConvertToHexError() +
              "||errStr - " + errStr.GetString() +
              "||outData - " + outData.GetString() +
              "||outVerifyInfo - " + outVerifyInfo.GetString() +
              "||count bytes outCert - " + outCert.Length);
            }
            outDataStr = outData.GetString(); 
            if (!string.IsNullOrEmpty(outDataStr))
            {
                byte [] result = Convert.FromBase64String(outDataStr);
                _appLog.WriteLog("VerifyData return from method::: ||countBytes - " + result.Length);
                _appLog.WriteLog("Завершение метода GetFile on Linux");
                return result;
            }
            _appLog.WriteLog("Завершение метода GetFile on Linux");
            return null;
        }

        #region public methods
        public bool VerifyData(byte[] cms, UserCertInfo userCertInfo)
        {
            _appLog.WriteLog("Начало метода VerifyData on Linux");
            byte alias = 12;
            string base64Str = Convert.ToBase64String(cms);
            byte[] base64Cms = Encoding.UTF8.GetBytes(base64Str);
            sbyte[] inoutSign = (sbyte[])((Array)base64Cms);
            ulong codeError;
            byte[] errStr = new byte[MINLENTH];
            byte[] outCert = new byte[LENGTH];
            byte[] outData = new byte[base64Cms.Length];
            byte[] outVerifyInfo = new byte[MINLENTH];
            int outCertLength = LENGTH;
            int outDataLen = outData.Length;
            int outVerifyInfoLen = MINLENTH;
            byte[] inData = new byte[1];
            bool res = false;
            int kalkanFlag; //= 2322;
            string codeErrorStr;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                  //(int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            // Проверяем отметку времени
            userCertInfo.TSP_exists = ValidateTimeSignuture(cms);
            if (!userCertInfo.TSP_exists.Value)
            {
                return res;
            }

            // вытаскиваем сертификат для дальнейшей работы
            codeError = VerifyData(ref alias, kalkanFlag, ref inData[0], inData.Length, ref inoutSign[0], inoutSign.Length,
                                    out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                    inCertID, out outCert[0], out outCertLength);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("VerifyData Output::: " +
               "||kalkanFlag - " + kalkanFlag.ToString() +
               "||codeError - " + codeError.ConvertToHexError() +
               "||errStr - " + errStr.GetString() +
               "||outData - " + outData.GetString() +
               "||outVerifyInfo - " + outVerifyInfo.GetString() +
               "||count bytes outCert - " + outCert.Length);
            userCertInfo.ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME = codeError.SpecificCodeError(errStr.GetString(), "проверка успешная без флага KC_NOCHECKCERTTIME");
            codeErrorStr = codeError.ConvertToHexError();
           
           
            //if(codeErrorStr == "0x08F00042")
            //{
            //    bufSize = MINLENTH;
            //    kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
            //    codeError = VerifyData(ref alias, kalkanFlag, ref inData[0], inData.Length, ref inoutSign[0], inoutSign.Length,
            //                         out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
            //                         inCertID, out outCert[0], out outCertLength);
            //    codeError = KC_GetLastErrorString(ref errStr[0], ref bufSize);
            //    _appLog.WriteLog("VerifyData Output::: " +
            //   "||kalkanFlag - " + kalkanFlag.ToString() +
            //   "||codeError - " + codeError.ConvertToHexError() +
            //   "||errStr - " + errStr.GetString() +
            //   "||outData - " + outData.GetString() +
            //   "||outVerifyInfo - " + outVerifyInfo.GetString() +
            //   "||count bytes outCert - " + outCert.Length);
            //    userCertInfo.WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME = codeError.SpecificCodeError(errStr.GetString(), null);
            //}
            if (codeError == 0)
            {
                userCertInfo.CMSvalidateMessage = codeError.SpecificCodeError(errStr.GetString(), "Цифровая подпись прошла проверку");

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
                    if (!string.IsNullOrEmpty(Encoding.UTF8.GetString(outCert)))
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
                    userCertInfo.ExtraInfo = ex.Message + ": errStr: " + errStr.GetString();
                }
            }
            else
            {
                userCertInfo.CMSvalidateMessage = codeError.SpecificCodeError(errStr.GetString(), null);
            }
            _appLog.WriteLog("Завершение метода VerifyData on Linux");
            return res;
        }

        public UserCertInfo GetInfo(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetInfo on Linux");
            string outCert = "";
            UserCertInfo userCertInfo = null;
            // на основе этого списка будет извлекаться инфо из сертификата
            Dictionary<string, int> userInfoList = new UserCertInfo().UserInfoList();
            try
            {
                outCert = GetCertFromCms(cms);
                userCertInfo = GetUserInfo(outCert.GetBytes(), userInfoList);
                userCertInfo.SignTime = GetTimeSignuture(cms);

            }
            catch (Exception ex)
            {
                throw ex;
            }
            _appLog.WriteLog("Завершение метода GetInfo on Linux");
            return userCertInfo;
        }

        #endregion



        
        #region private methods
        private KeyValuePair<string, bool> ValidateSertificate_OCSP(byte[] cert)
        {
            _appLog.WriteLog("Начало метода ValidateSertificate_OCSP on Linux");
            int oCSPType = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            byte[] outInfo = new byte[MINLENTH];
            byte[] ocspPath = new byte[OCSP_PATH.Length];
            int outInfoLength = MINLENTH;
            ocspPath = System.Text.Encoding.UTF8.GetBytes(OCSP_PATH);
            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            int bufSize = MINLENTH;

            // Clean byte[] cert from empty bytes(0)
            var certString = cert.GetString();
            cert = certString.GetBytes();

            codeError = X509ValidateCertificate(ref cert[0], cert.Length, oCSPType, ref ocspPath[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("X509ValidateCertificate Output::: " +
              "||ocspPath - " + ocspPath.GetString() +
              "||codeError - " + codeError.ConvertToHexError() +
              "||errStr - " + errStr.GetString() +
              "||outInfo - " + outInfo.GetString());
            if (codeError == 0)
            {
                keyValue = codeError.SpecificCodeError(errStr.GetString(), CENTER_DETERMINED_MESSAGE);
            }
            else
            {
                keyValue = codeError.SpecificCodeError(errStr.GetString(),null);
            }
            _appLog.WriteLog("Завершение метода ValidateSertificate_OCSP on Linux");
            return keyValue;
            //return Encoding.UTF8.GetString(outInfo, 0, outInfoLength - 1);
        }

        private KeyValuePair<string, bool> ValidateSertificate_CRl(byte[] cert)
        {
            _appLog.WriteLog("Начало метода ValidateSertificate_CRl on Linux");
            string alg;
            int cRLPType = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            byte[] outInfo = new byte[MINLENTH];
            byte[] outAlg = new byte[MINLENTH];
            int outInfoLength = MINLENTH;
            int outAlgLength= MINLENTH;
            string pathRSA = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "crlFiles", "nca_rsa.crl");
            string pathGOST = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "crlFiles", "nca_gost.crl");
            byte[] crlPathRSA = new byte[pathRSA.Length];
            byte[] crlPathGOST = new byte[pathGOST.Length];
            crlPathRSA = Encoding.UTF8.GetBytes(pathRSA);
            crlPathGOST = Encoding.UTF8.GetBytes(pathGOST);
            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            int bufSize = MINLENTH;

            // Clean byte[] cert from empty bytes(0)
            var certString = cert.GetString();
            cert = certString.GetBytes();

            // узнаем алгоритм шифрования
            codeError = X509CertificateGetInfo(ref cert[0], cert.Length, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out outAlg[0], ref outAlgLength);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("Алгоритм шифрования - " + outAlg.GetString());
            if (codeError != 0)
            {
                throw new Exception($"err: {codeError.ConvertToHexError()} and discription errStr: {errStr.GetString()}");
            }
            // на основе алгоритма шифрование выберем соответствующий crl файл
            alg = Encoding.UTF8.GetString(outAlg, 0, outAlgLength - 1);
            if (alg.Contains("RSA"))
            {
                bufSize = MINLENTH;
                codeError = X509ValidateCertificate(ref cert[0], cert.Length, cRLPType, ref crlPathRSA[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
                KC_GetLastErrorString(ref errStr[0], ref bufSize);
                _appLog.WriteLog("X509ValidateCertificate Output::: " +
               "||crlPathRSA - " + crlPathRSA.GetString() +
               "||codeError - " + codeError.ConvertToHexError() +
               "||errStr - " + errStr.GetString() +
               "||outInfo - " + outInfo.GetString());
                if (codeError == 0)
                {
                    keyValue = codeError.SpecificCodeError(errStr.GetString(), CENTER_DETERMINED_MESSAGE);
                }
                else
                {
                    keyValue = codeError.SpecificCodeError(errStr.GetString(), null);
                }
            }
            else if (alg.Contains("GOST"))
            {
                bufSize = MINLENTH;
                outInfoLength = MINLENTH;
                codeError = X509ValidateCertificate(ref cert[0], cert.Length, cRLPType, ref crlPathGOST[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
                KC_GetLastErrorString(ref errStr[0], ref bufSize);
                _appLog.WriteLog("X509ValidateCertificate Output::: " +
               "||crlPathGOST - " + crlPathGOST.GetString() +
               "||codeError - " + codeError.ConvertToHexError() +
               "||errStr - " + errStr.GetString() +
               "||outInfo - " + outInfo.GetString());
                if (codeError == 0)
                {
                    keyValue = codeError.SpecificCodeError(errStr.GetString(), CENTER_DETERMINED_MESSAGE);
                }
                else
                {
                    keyValue = codeError.SpecificCodeError(errStr.GetString(), null);
                }
            }
            else
            {
                throw new Exception($"Такого алгоритма шифрования как {alg} не существует");
            }
            _appLog.WriteLog("Завершение метода ValidateSertificate_CRl on Linux");
            return keyValue;
        }

        private DateTime GetTimeSignuture(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetTimeSignuture on Linux");
            string base64Str = Convert.ToBase64String(cms);
            byte[] base64Cms = Encoding.UTF8.GetBytes(base64Str);
            byte[] errStr = new byte[MINLENTH];
            long outDateTime;
            ulong codeError;
            int kalkanFlag; //= 2322;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                  //(int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;

            codeError = KC_GetTimeFromSig(ref base64Cms[0], base64Cms.Length, kalkanFlag, 0, out outDateTime);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("KC_GetTimeFromSig Output::: " +
            "||kalkanFlag - " + kalkanFlag.ToString() +
            "||codeError - " + codeError.ConvertToHexError() +
            "||errStr - " + errStr.GetString() +
            "||outDateTime - " + dateTime.AddSeconds(outDateTime).ToLocalTime().ToString());
            if (codeError == 0)
            {
                _appLog.WriteLog("Завершение метода GetTimeSignuture on Linux");
                return dateTime.AddSeconds(outDateTime).ToLocalTime();
            }
            else
            {
                return new DateTime();
                // throw new Exception($"err: {codeError.ConvertToHexError()} and discription errStr: {errStr.GetString()}");
            }
        }

        private KeyValuePair<string, bool> ValidateTimeSignuture(byte[] cms)
        {
            _appLog.WriteLog("Начало метода ValidateTimeSignuture on Linux");
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>(null, false);
            string base64Str = Convert.ToBase64String(cms);
            byte[] base64Cms = Encoding.UTF8.GetBytes(base64Str);
            byte[] errStr = new byte[MINLENTH];
            long outDateTime;
            ulong codeError;
            int kalkanFlag; //= 2322;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                  //(int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;

            codeError = KC_GetTimeFromSig(ref base64Cms[0], base64Cms.Length, kalkanFlag, 0, out outDateTime);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("KC_GetTimeFromSig Output::: " +
             "||kalkanFlag - " + kalkanFlag.ToString() +
             "||codeError - " + codeError.ConvertToHexError() +
             "||errStr - " + errStr.GetString() +
             "||outDateTime - " + outDateTime.ToString());
            if (codeError == 0)
            {
                keyValue = new KeyValuePair<string, bool>("Успешно", true);
                _appLog.WriteLog("Завершение метода ValidateTimeSignuture on Linux");
                return keyValue;
            }
            else
            {
                keyValue = new KeyValuePair<string, bool>("Не успешно", false);
                _appLog.WriteLog("Завершение метода ValidateTimeSignuture on Linux");
                return keyValue;
                // throw new Exception($"err: {codeError.ConvertToHexError()} and discription errStr: {errStr.GetString()}");
            }
        }

        private string GetCertFromCms(byte[] cms)
        {
            _appLog.WriteLog("Начало метода GetCertFromCms on Linux");
            string base64Str = Convert.ToBase64String(cms);
            byte[] base64Cms = Encoding.UTF8.GetBytes(base64Str);
            byte[] outCert = new byte[LENGTH];
            int outCertLength = LENGTH;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64;
                   //(int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            int bufSize = MINLENTH;
            KC_GetCertFromCMS(ref base64Cms[0], base64Cms.Length, 1, kalkanFlag, out outCert[0], out outCertLength);
            codeError = KC_GetLastErrorString(ref errStr[0], ref bufSize);
            _appLog.WriteLog("KC_GetCertFromCMS Output::: " +
              "||kalkanFlag - " + kalkanFlag.ToString() +
              "||codeError - " + codeError.ConvertToHexError() +
              "||errStr - " + errStr.GetString() +
              "||count bytes outCert - " + outCert.Length);

            if (codeError == 0)
            {
                _appLog.WriteLog("Завершение метода GetCertFromCms on Linux");
                //  return Encoding.UTF8.GetString(outCert, 0, outCertLength);
                return outCert.GetString();
            }
            else
            {
                throw new Exception($"err: {codeError.ConvertToHexError()} and discription errStr: {errStr.GetString()}");
            }
           
        }

        private UserCertInfo GetUserInfo(byte[] cert, Dictionary<string, int> userInfoList)
        {
            _appLog.WriteLog("Начало метода GetUserInfo on Linux");
            UserCertInfo userCertInfo = new UserCertInfo();
            Type type = typeof(UserCertInfo);
            byte[] outData = new byte[MINLENTH];
            int outDataLength = MINLENTH;
            ulong codeError;
            string res;
            try
            {
                var certString = cert.GetString();
                cert = certString.GetBytes();
                foreach (var info in userInfoList)
                {
                    codeError = X509CertificateGetInfo(ref cert[0], cert.Length, info.Value, out outData[0], ref outDataLength);
                    _appLog.WriteLog("X509CertificateGetInfo output::: "+ 
                        "||KALKANCRYPTCOM_CERTPROPID - " + info.Value.ToString() +
                        "||outData - " + outData.GetString());
                    //  res = Encoding.UTF8.GetString(outData, 0, outDataLength);
                    //res = Encoding.UTF8.GetString(outData);
                    res = outData.GetString();
                    PropertyInfo property = type.GetProperty(info.Key);
                    property.SetValue(userCertInfo, res);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            _appLog.WriteLog("Завершение метода GetUserInfo on Linux");
            return userCertInfo;
        }

        private bool SaveExtractedDataFromCMSToFile(byte[] data)
        {
            bool res = false;
            try
            {
                //byte[] bytesFromBase64 = Convert.FromBase64String(Encoding.UTF8.GetString(data));
                byte[] bytesFromBase64 = Convert.FromBase64String(data.GetString());
                System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.CurrentDirectory, "sometext.txt"), bytesFromBase64);
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