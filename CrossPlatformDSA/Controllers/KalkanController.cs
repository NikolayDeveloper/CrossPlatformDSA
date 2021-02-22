using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CrossPlatformDSA.DSA.Interfaces;
using CrossPlatformDSA.DSA.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CrossPlatformDSA.Controllers
{
    public class KalkanController : Controller
    {
        private readonly IECPService _espService;
        public KalkanController(IECPService espService)
        {
            _espService = espService;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult VerifyCMS([Required]IFormFile file)
        {
            byte [] cms;
            Stream stream= file.OpenReadStream();
            UserCertInfo userCertInfo = new UserCertInfo();
            using (BinaryReader sr = new BinaryReader(stream))
            {
                cms = sr.ReadBytes(Convert.ToInt32(stream.Length));
            }
            try
            {
                // здесь просто получим подписанные данные из cms
                //byte[] data =  _espService.GetFile(cms);
                
                // здесь получим информацию о сертификате из cms
                 userCertInfo = _espService.GetInfo(cms);
                
                // здесь проверим подпись на целостность, отозванность, просроченность
                if (_espService.VerifyData(cms, userCertInfo))
                {
                    ViewBag.Message = "Проверка прошла успешно";
                }
                else
                {
                    ViewBag.Message = "Проверка не прошла успешно";
                }


            }
            catch (Exception ex)
            {
                // ViewBag.Message += ex.Message;
                userCertInfo.ExtraInfo = ex.Message;
                //ViewBag.InnerException=ex.InnerException;
            }
            ViewBag.Platform = Environment.OSVersion.Platform.ToString();
            return View(userCertInfo);
        }
        [HttpPost]
        public FileResult GetFile()
        {
            return PhysicalFile(Path.Combine(Environment.CurrentDirectory, "sometext.txt"), "application/octet-stream", "downloadFile.txt");
        }
    }
}