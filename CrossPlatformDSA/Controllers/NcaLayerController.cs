using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CrossPlatformDSA.DSA.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CrossPlatformDSA.Controllers
{
    public class NcaLayerController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<string> FileForCMS([Required]IFormFile file)
        {
            string contextOfFile;
            Stream stream = file.OpenReadStream();
            try
            {
                using (StreamReader sr = new StreamReader(stream))
                {
                    contextOfFile = await sr.ReadToEndAsync();
                    Preserver.data = Protector.Encrypt(contextOfFile, "passwordForEncryption");
                }
            }
            catch (Exception ex)
            {

                var dsf = ex.Message;
            }
            
            //string sdg = Protector.Decrypt(Preserver.data, "passwordForEncryption");
            return Preserver.data;
        }
    }
}