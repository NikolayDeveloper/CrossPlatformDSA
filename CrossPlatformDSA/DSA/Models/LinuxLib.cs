﻿using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class LinuxLib : ILibrary
    {
        const string LIB_NAME = "kalkancryptwr-64";
        const int LENGTH = 64768;
        byte[] outData = new byte[LENGTH],
        errStr = new byte[LENGTH],
        outVerifyInfo = new byte[LENGTH],
        outCert = new byte[LENGTH],
        outSign = new byte[LENGTH],
        signNodeId = new byte[LENGTH],
        parentSignNode = new byte[LENGTH],
        parentNameSpace = new byte[LENGTH],
        outDataInfo = new byte[LENGTH];
        int inCertID = 1;
        int bufSize = 1000;
        int outDataLen = LENGTH,
        outVerifyInfoLen = LENGTH,
        outCertLength = LENGTH,
        outSignLength = LENGTH,
        outDataInfoLength=LENGTH;

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
        public static extern long KC_GetTimeFromSig(ref byte inData, int inDataLength, int flags, int inSigId, out  long outDateTime);
        public bool VerifyData(byte[] data,out UserCertInfo userCertInfo)
        {
            string signRusForCheck="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";
            userCertInfo = null;
            byte[] dataRandom = { 100, 97, 116, 97 };
            //  string signuture3="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";
            bool res = false;
            int kalkanFlag; //= 2322;
            string base64Str, str;
            byte[] arr;
            base64Str = Convert.ToBase64String(data);
            if(signRusForCheck==base64Str)
            {
                System.Console.WriteLine(   "Nice");
            }
            arr = base64Str.GetBytes();
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 + 
                  (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            Init();
            KC_TSASetUrl($"http://tsp.pki.gov.kz:80");
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            var f2 = VerifyData("", kalkanFlag, ref dataRandom[0], dataRandom.Length, out arr[0], arr.Length,
                                out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                inCertID, out outCert[0], out outCertLength);
            string hexErr = f2.ConvertToHexError();

            var d1 = outData.GetString();
            var d2 = outVerifyInfo.GetString();
            var d3 = outCert.GetString();
            bufSize = 1000;
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            str = errStr.GetString();
            
              if(str=="")
            {
                res = true;
                try
                {
                    userCertInfo = GetUserCertificate(outCert,ref arr[0]);


                    byte[]bytesFromBase64 = Convert.FromBase64String(outData.GetString());
                    System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.CurrentDirectory,"sometext.txt"), bytesFromBase64);


                }
                catch (Exception ex)
                {
                    userCertInfo = new UserCertInfo();
                    userCertInfo.extraInfo = ex.Message;
                }
               

            }
            else
            {
                userCertInfo= new UserCertInfo();
                userCertInfo.extraInfo="error: "+str+" || outdata: "+d1+" || outverifyInfo: "+d2+" || outCert: "+d3;
            }
            return res;
        }
        public UserCertInfo GetUserCertificate(byte[] cert, ref byte base64ByteCMS)
        {
            string str;

            UserCertInfo userCertInfo = new UserCertInfo();
            var f= X509CertificateGetInfo(ref cert[0], outCertLength, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME,out outDataInfo[0],ref outDataInfoLength);
            //userCertInfo.nameAndSurname=outDataInfo.GetString();
            userCertInfo.nameAndSurname = System.Text.Encoding.UTF8.GetString(outDataInfo, 0, outDataInfoLength-1);


         
            {
                outDataInfoLength = 1000;
                var f2 = X509CertificateGetInfo(
                     ref cert[0], outCertLength,
                     (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME,
                     out outDataInfo[0],
                     ref outDataInfoLength
                    );

            }

            userCertInfo.middleName= System.Text.Encoding.UTF8.GetString(outDataInfo,0,outDataInfoLength-1);
            outDataInfoLength =1000;
            str= f.ConvertToHexError();
            bufSize = 1000;

            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            str = errStr.GetString();
           
            str= outDataInfo.GetString();

            return userCertInfo;
        }
    }
}