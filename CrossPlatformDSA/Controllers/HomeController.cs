﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using CrossPlatformDSA.Models;
using CrossPlatformDSA.DSA.Interfaces;

namespace CrossPlatformDSA.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILibrary _lib;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger,ILibrary library)
        {
            _lib = library;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
