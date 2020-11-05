using CrossPlatformDSA.DSA.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Interfaces
{
    public interface ILibrary
    {
       bool VerifyData(byte[] data,out UserCertInfo userCertInfo);
    }
}
