﻿using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class ECPServiceLinux : IECPService
    {
        public ECPServiceLinux()
        {
            Init();
            KC_TSASetUrl($"http://tsp.pki.gov.kz:80");
        }
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем
        public string CENTER_DETERMINED_MESSAGE = "Удостоверяющий центр опознан";
        private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
        const string LIB_NAME = "kalkancryptwr-64";
        const int LENGTH = 64768;
        const int MINLENTH = 2000;
        //byte[] outData = new byte[LENGTH],
       // errStr = new byte[LENGTH],
       // byte[] outVerifyInfo = new byte[LENGTH],
        //outCert = new byte[LENGTH],
        //byte[] outSign = new byte[LENGTH],
        //signNodeId = new byte[LENGTH],
        //parentSignNode = new byte[LENGTH],
        //parentNameSpace = new byte[LENGTH],
        //outDataInfo = new byte[LENGTH];
       // ocspPath = new byte[LENGTH],
       // outInfo = new byte[LENGTH];
        int inCertID = 1;
        //int bufSize = 10000;
        
       // long currentLocalUnixTime;
        //int outDataLen = LENGTH,
        //int outVerifyInfoLen = LENGTH,
        // outCertLength = LENGTH,
        //int outSignLength = LENGTH,
       // outDataInfoLength = LENGTH;
       // outInfoLength=LENGTH;
        
        


         [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong Init();

        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern void KC_TSASetUrl(string tsaurl);

        [DllImport(LIB_NAME, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong KC_GetLastErrorString(ref byte errorString, ref int bufSize);

        [DllImport(LIB_NAME, CallingConvention = CallingConvention.StdCall)]
        public static extern ulong VerifyData(string alias, int flags, ref byte inData, int inDataLength, out byte inoutSign, int inoutSignLength,
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



        #region public methods
        public bool VerifyData(byte[] cms, UserCertInfo userCertInfo)
        {
            userCertInfo = null;
            ulong codeError;
            byte[] errStr = new byte[MINLENTH];
            byte[] outCert = new byte[LENGTH];
            byte[] outData = new byte[cms.Length];
            byte[] outVerifyInfo = new byte[MINLENTH];
            int outCertLength = LENGTH;
            int outDataLen = outData.Length;
            int outVerifyInfoLen = MINLENTH;
            string signRusForCheck="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";
            byte[] dataRandom = { 100, 97, 116, 97 };
            bool res = false;
            int kalkanFlag; //= 2322;
            string codeErrorStr;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 + 
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            
            codeError = VerifyData("", kalkanFlag, ref dataRandom[0], dataRandom.Length, out cms[0], cms.Length,
                                    out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                    inCertID, out outCert[0], out outCertLength);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            userCertInfo.ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME = codeError.SpecificCodeError(Encoding.UTF8.GetString(errStr), "проверка успешная без флага KC_NOCHECKCERTTIME");
            codeErrorStr = codeError.ConvertToHexError();
            if(codeErrorStr == "0x08F00042")
            {
                bufSize = MINLENTH;
                kalkanFlag |= (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_NOCHECKCERTTIME;
                codeError = VerifyData("", kalkanFlag, ref dataRandom[0], dataRandom.Length, out cms[0], cms.Length,
                                     out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                     inCertID, out outCert[0], out outCertLength);
                KC_GetLastErrorString(ref errStr[0], ref bufSize);

                userCertInfo.WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME = codeError.SpecificCodeError(Encoding.UTF8.GetString(errStr), null);
            }
            if (codeError == 0)
            {
                userCertInfo.CMSvalidateMessage = codeError.SpecificCodeError(Encoding.UTF8.GetString(errStr), "Цифровая подпись прошла проверку");

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
                userCertInfo.CMSvalidateMessage = codeError.SpecificCodeError(errStr.GetString(), null);
            }
            
            return res;
        }

        public UserCertInfo GetInfo(byte[] cms)
        {
            string outCert = "";
            // UserCertInfo userCertInfo = new UserCertInfo();
            UserCertInfo userCertInfo = null;
            Dictionary<string, int> userInfoList = new UserCertInfo().UserInfoList();
            try
            {
                outCert = GetCertFromCms(cms);
                userCertInfo = GetUserInfo(Encoding.UTF8.GetBytes(outCert), userInfoList);
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
        private KeyValuePair<string, bool> ValidateSertificate_OCSP(byte[] cert)
        {
            int oCSPType = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            byte[] outInfo = new byte[MINLENTH];
            byte[] ocspPath = new byte[OCSP_PATH.Length];
            int outInfoLength = MINLENTH;
            ocspPath = System.Text.Encoding.UTF8.GetBytes(OCSP_PATH);
            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            codeError = X509ValidateCertificate(ref cert[0], cert.Length, oCSPType, ref ocspPath[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
            int bufSize = MINLENTH;
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            if (codeError == 0)
            {
                keyValue = codeError.SpecificCodeError(errStr.GetString(), CENTER_DETERMINED_MESSAGE);
            }
            else
            {
                keyValue = codeError.SpecificCodeError(errStr.GetString(),null);
            }

            return keyValue;
            //return Encoding.UTF8.GetString(outInfo, 0, outInfoLength - 1);
        }

        private KeyValuePair<string, bool> ValidateSertificate_CRl(byte[] cert)
        {
            string alg;
            int cRLPType = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_CRL;
            KeyValuePair<string, bool> keyValue = new KeyValuePair<string, bool>();
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            byte[] outInfo = new byte[MINLENTH];
            byte[] outAlg = new byte[MINLENTH];
            int outInfoLength = MINLENTH;
            int outAlgLength= MINLENTH;
            string pathRSA = Path.Combine(Environment.CurrentDirectory, "nca_rsa.crl");
            string pathGOST = Path.Combine(Environment.CurrentDirectory, "nca_gost.crl");
            byte[] crlPathRSA = new byte[pathRSA.Length];
            byte[] crlPathGOST = new byte[pathGOST.Length];
            crlPathRSA = Encoding.UTF8.GetBytes(pathRSA);
            crlPathGOST = Encoding.UTF8.GetBytes(pathGOST);
            long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            int bufSize = MINLENTH;
            // узнаем алгоритм шифрования
            codeError = X509CertificateGetInfo(ref cert[0], cert.Length, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out outAlg[0], ref outAlgLength);
            
            KC_GetLastErrorString(ref errStr[0], ref bufSize);

            if (codeError != 0)
            {
                throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr.GetString()}");
            }
            // на основе алгоритма шифрование выберем соответствующий crl файл
            alg = Encoding.UTF8.GetString(outAlg, 0, outAlgLength - 1);
            if (alg.Contains("RSA"))
            {
                codeError = X509ValidateCertificate(ref cert[0], cert.Length, cRLPType, ref crlPathRSA[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
                bufSize = MINLENTH;
                KC_GetLastErrorString(ref errStr[0], ref bufSize);
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
                outInfoLength = MINLENTH;
                codeError = X509ValidateCertificate(ref cert[0], cert.Length, cRLPType, ref crlPathGOST[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
                bufSize = MINLENTH;
                KC_GetLastErrorString(ref errStr[0], ref bufSize);
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
            return keyValue;
        }

        private DateTime GetTimeSignuture(byte[] cms)
        {
            byte[] errStr = new byte[MINLENTH];
            long outDateTime;
            ulong codeError;
            int kalkanFlag; //= 2322;
            int bufSize = MINLENTH;
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;

            codeError = KC_GetTimeFromSig(ref cms[0], cms.Length, kalkanFlag, 0, out outDateTime);
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            if (codeError == 0)
            {
                return dateTime.AddSeconds(outDateTime).ToLocalTime();
            }
            else
            {
                throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr.GetString()}");
            }
        }

        private string GetCertFromCms(byte[] cms)
        {
            byte[] outCert = new byte[LENGTH];
            int outCertLength = LENGTH;
            int kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 |
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            byte[] errStr = new byte[MINLENTH];
            ulong codeError;
            codeError = KC_GetCertFromCMS(ref cms[0], cms.Length, 1, kalkanFlag, out outCert[0], out outCertLength);
            if (codeError == 0)
            {
                return Encoding.UTF8.GetString(outCert, 0, outCertLength - 1);
            }
            else
            {
                throw new Exception($"err: {codeError.ToString()} and discription errStr: {errStr.GetString()}");
            }
        }

        private UserCertInfo GetUserInfo(byte[] cert, Dictionary<string, int> userInfoList)
        {
            UserCertInfo userCertInfo = new UserCertInfo();
            Type type = typeof(UserCertInfo);
            byte[] outData = new byte[MINLENTH];
            int outDataLength = MINLENTH;
            ulong codeError;
            string res;
            try
            {
                foreach (var info in userInfoList)
                {
                    codeError = X509CertificateGetInfo(ref cert[0], cert.Length, info.Value, out outData[0], ref outDataLength);
                    res = Encoding.UTF8.GetString(outData, 0, outDataLength - 1);
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

        private bool SaveExtractedDataFromCMSToFile(byte[] data)
        {
            bool res = false;
            try
            {
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



        //private KeyValuePair<string,string> GetUserInfo(byte[] cert,int certPropIdFlag)
        //{
        //    outDataInfoLength = LENGTH;
        //    KeyValuePair<string, string> res=new KeyValuePair<string, string>("default", "default");
        //    ulong isSuccess = X509CertificateGetInfo(ref cert[0], cert.Length, certPropIdFlag, out outDataInfo[0], ref outDataInfoLength);
        //    if(isSuccess==0)
        //    {
        //        if(!string.IsNullOrEmpty(Encoding.UTF8.GetString(outDataInfo)))
        //        {
        //            //TODO parse string outDataInfo to key and value
        //            res = new KeyValuePair<string, string>("key", Encoding.UTF8.GetString(outDataInfo, 0, outDataInfoLength - 1));
        //        }
        //    }
        //    else
        //    {
        //        res = new KeyValuePair<string, string>("error","Error: " + isSuccess.ConvertToHexError());
        //    }
        //    return res;
        //}

        #endregion



        public byte[] GetFile(byte[] cms)
        {
            throw new NotImplementedException();
        }

        //public string ValidateSertificate(byte[] outCert)
        //{
        //    byte[] errStr = new byte[LENGTH];
        //    ulong codeError;
        //    byte[] outInfo = new byte[LENGTH];
        //    byte[] ocspPath = new byte[LENGTH];
        //    int outInfoLength = LENGTH;
        //    ocspPath = System.Text.Encoding.UTF8.GetBytes(OCSP_PATH);
        //    long currentLocalUnixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
        //    codeError = X509ValidateCertificate(ref outCert[0], outCert.Length, oCSPType, ref ocspPath[0], currentLocalUnixTime, out outInfo[0], out outInfoLength);
        //    if(codeError!=0)
        //    {
        //        bufSize = 1000;
        //        KC_GetLastErrorString(ref errStr[0], ref bufSize);
        //        throw new Exception("Ошибка в методе VerifyData,код ошибки: " + codeError.ConvertToHexError(),
        //                            new Exception(Encoding.UTF8.GetString(errStr)));
        //    }

        //    return Encoding.UTF8.GetString(outInfo,0, outInfoLength - 1);
        //}

        //public UserCertInfo GetAllInfo(byte[] cms)
        //{
        //    long unixTimeSignuture;
        //    string certStr = "";
        //    byte[] outCert = new byte[LENGTH];

        //    try
        //    {
        //      certStr = GetCertFromCms(cms);
        //      outCert = Encoding.UTF8.GetBytes(certStr);
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception(ex.Message + " InnerExeption: " + ex.InnerException);
        //    }


        //    UserCertInfo userCertInfo = new UserCertInfo();
        //    userCertInfo.nameAndSurname = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME).Value;
        //    userCertInfo.middleName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME).Value;
        //    userCertInfo.issuerCountryName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COUNTRYNAME).Value;
        //    userCertInfo.issuerSopn = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_SOPN).Value;
        //    userCertInfo.issuerLocalityName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_LOCALITYNAME).Value;
        //    userCertInfo.issuerOrgName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORG_NAME).Value;
        //    userCertInfo.issuerOrgUnitName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORGUNIT_NAME).Value;
        //    userCertInfo.issuerCommonName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COMMONNAME).Value;
        //    userCertInfo.subjectCountryName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COUNTRYNAME).Value;
        //    userCertInfo.subjectSopn = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SOPN).Value;
        //    userCertInfo.subjectLocalityName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_LOCALITYNAME).Value;
        //    userCertInfo.surname = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SURNAME).Value;
        //    userCertInfo.serialNumberCert = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SERIALNUMBER).Value;
        //    userCertInfo.email = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_EMAIL).Value;
        //    userCertInfo.subjectOrgName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORG_NAME).Value;
        //    userCertInfo.subjectOrgUnitName = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORGUNIT_NAME).Value;
        //    userCertInfo.subjectBc = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_BC).Value;
        //    userCertInfo.subjectDc = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DC).Value;
        //    userCertInfo.notBefore = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTBEFORE).Value;
        //    userCertInfo.notAfter = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTAFTER).Value;
        //    userCertInfo.keyUsage = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_KEY_USAGE).Value;
        //    userCertInfo.extKeyUsage = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_EXT_KEY_USAGE).Value;
        //    userCertInfo.authKeyId = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_AUTH_KEY_ID).Value;
        //    userCertInfo.subjKeyId = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJ_KEY_ID).Value;
        //    userCertInfo.certSn = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN).Value;
        //    userCertInfo.issuerDn = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_DN).Value;
        //    userCertInfo.subjectDn = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DN).Value;
        //    userCertInfo.signatureAlg = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG).Value;
        //    userCertInfo.pubkey = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_PUBKEY).Value;
        //    userCertInfo.policiesId = GetUserInfo(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_POLICIES_ID).Value;

        //    unixTimeSignuture = GetTimeSignuture(cms);
        //    userCertInfo.signTime = dateTime.AddSeconds(unixTimeSignuture).ToLocalTime();


        //    return userCertInfo;
        //}








        //public UserCertInfo GetInfo(byte[] cms)
        //{
        //    throw new NotImplementedException();
        //}
    }
}