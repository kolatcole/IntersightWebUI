using IntersightWebUI.Components;
using IntersightWebUI.Components.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using System.Collections.Generic;
using static IntersightWebUI.Components.Pages.Weather;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;


var builder = WebApplication.CreateBuilder(args);
string[] initialScopes = builder
                .Configuration.GetSection("DownstreamApi:Scopes")?
                .Get<List<string>>()
                .ToArray();
builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
                .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
                .AddDownstreamApi("DownstreamApi", builder.Configuration.GetSection("DownstreamApi"))
                .AddInMemoryTokenCaches();


builder.Services.AddScoped<IdentityRedirectManager>();
//builder.Services.AddScoped<GraphApiService>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();
builder.Services.AddFluentUIComponents();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddCascadingAuthenticationState();
//builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, PersistingRevalidatingAuthenticationStateProvider>();

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
}).AddMicrosoftIdentityUI();
// Add services to the container.

builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents()
    .AddInteractiveServerComponents();

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor()
        .AddMicrosoftIdentityConsentHandler();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//app.Use(async (context, next) =>
//{
//    if (context.Request.Path == "/signin-oidc" && context.Request.Query.ContainsKey("admin_consent"))
//    {
//        var adminConsent = context.Request.Query["admin_consent"].ToString();
//        var tenantId = context.Request.Query["tenant"].ToString();

//        if (adminConsent == "True")
//        {
//            // Handle admin consent logic here
//            // For example, you could log the tenant ID or perform any required actions
//            Console.WriteLine($"Admin consent granted for tenant: {tenantId}");
//        }

//        // Redirect to the original URL or a specific page after handling admin consent
//        var returnUrl = context.Request.Host.ToString()+ context.Request.Path.ToString()+context.Request.QueryString.ToString();
//        context.Response.Cookies.Delete("ReturnUrl");

//        if (!string.IsNullOrEmpty(returnUrl))
//        {
//            context.Response.Redirect(returnUrl);
//            return;
//        }
//        else
//        {
//            context.Response.Redirect("/");
//            return;
//        }
//    }

//    await next.Invoke();
//});

//app.MapFallbackToPage(pattern: @"..\..\Components\Layout", page:"/Login");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.UseStaticFiles();
app.UseAntiforgery();
app.MapControllers();


app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode().AddInteractiveWebAssemblyRenderMode();

app.Run();
