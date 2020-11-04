using CrossPlatformDSA.DSA.Interfaces;
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
        parentNameSpace = new byte[LENGTH];
        int inCertID = 1;
        int bufSize = 1000;
        int outDataLen = LENGTH,
        outVerifyInfoLen = LENGTH,
        outCertLength = LENGTH,
        outSignLength = LENGTH;

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
        public bool VerifyData(byte[] data,out UserCertInfo userCertInfo)
        {
            userCertInfo = null;
            byte[] dataRandom = { 100, 97, 116, 97 };
            //  string signuture3="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";
            bool res = false;
            int kalkanFlag = 2322;
            string base64Str, str;
            byte[] arr;
            base64Str = Convert.ToBase64String(data);
            arr = base64Str.GetBytes();
            Init();
            KC_TSASetUrl($"http://tsp.pki.gov.kz:80");
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            var f2 = VerifyData("", kalkanFlag, ref dataRandom[0], dataRandom.Length, out arr[0], arr.Length,
                                out outData[0], out outDataLen, out outVerifyInfo[0], out outVerifyInfoLen,
                                inCertID, out outCert[0], out outCertLength);
            string hexErr = Extention.ConvertToHexError(f2);
            var d1 = outData.GetString();
            var d2 = outVerifyInfo.GetString();
            var d3 = outCert.GetString();
            bufSize = 1000;
            KC_GetLastErrorString(ref errStr[0], ref bufSize);
            str = errStr.GetString();
            if (str == "")
            {
                res = true;
            }
            return res;
        }
    }
}
