using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using JsClient.Models;

namespace JsClient.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpGet("/SigninCallback")]
    public IActionResult SigninCallback()
    {
        return View();
    }
    [HttpGet("/SignOutCallback")]
    public IActionResult SignOutCallback()
    {
        return View();
    }
    [HttpGet("/SigninSilentCallback")]
    public IActionResult SigninSilentCallback()
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