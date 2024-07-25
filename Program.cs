using sico.data;
using sico.models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using System.Security.Cryptography.Xml;
using System.Text.Json.Serialization;
using sico.clases;
using Serilog;
using Keycloak.AuthServices.Authentication;
using Keycloak.AuthServices.Authorization;
using System.Text.Json;




var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();



builder.Services.AddKeycloakWebApiAuthentication(builder.Configuration);

builder.Services
    .AddAuthorization()
    .AddKeycloakAuthorization(builder.Configuration)
    .AddAuthorizationServer(builder.Configuration);


builder.Services.AddCors();

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
   
    //Titulo
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "API Gateway SICO", Version = "v1" });
    //KeyCloak
    //c.CustomSchemaIds(type => type.ToString());
    //var securityScheme = new OpenApiSecurityScheme
    //{
    //    Name = "KEYCLOAK",
    //    Type = SecuritySchemeType.OAuth2,
    //    In = ParameterLocation.Header,
    //    BearerFormat = "JWT",
    //    Scheme = "bearer",
    //    Flows = new OpenApiOAuthFlows
    //    {
    //        AuthorizationCode = new OpenApiOAuthFlow
    //        {
    //            AuthorizationUrl = new Uri(builder.Configuration["Jwt:AuthorizationUrl"]),
    //            TokenUrl = new Uri(builder.Configuration["Jwt:TokenUrl"]),
    //            Scopes = new Dictionary<string, string> { }
    //        }
    //    },
    //    Reference = new OpenApiReference
    //    {
    //        Id = JwtBearerDefaults.AuthenticationScheme,
    //        Type = ReferenceType.SecurityScheme
    //    }
    //};
    //Boton Autorizacion
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Jwt Authorization",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }

                    },
                    new string[] {}
                }
            });
});

var connectionString = Seguridad.getDecode(builder.Configuration.GetConnectionString("Postgres_Db"));

builder.Services.AddDbContext<SicoDbContext>(options =>
{
    options.UseNpgsql(connectionString);
    options.EnableSensitiveDataLogging();
});

/*builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Seguridad.getDecode(builder.Configuration["Jwt:Key"])))
    };
});*/

// KeyCloak
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
//}).AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
//    o =>
//    {
//        o.Authority = builder.Configuration["Jwt:Authority"];
//        o.Audience = builder.Configuration["Jwt:Audience"];
//        o.RequireHttpsMetadata = false;
//        o.Events = new JwtBearerEvents()
//        {
//            OnAuthenticationFailed = c =>
//            {
//                c.NoResult();

//                c.Response.StatusCode = 401;
//                c.Response.ContentType = "application/json";

//                // Debug only for security reasons
//                var message = "Authentication failed: " + c.Exception.Message;
//                var errorResponse = JsonSerializer.Serialize(new { message });
//                return c.Response.WriteAsync(errorResponse);

//                //return c.Response.WriteAsync("An error occured processing your authentication.");
//            }
//        };
//    }
//    );


builder.Services.AddControllers().AddJsonOptions(x =>
                x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);

builder.Services.AddAWSLambdaHosting(LambdaEventSource.HttpApi);

builder.Configuration.AddEnvironmentVariables();

var logger = new LoggerConfiguration()
  .ReadFrom.Configuration(builder.Configuration)
  .Enrich.FromLogContext()
  .CreateLogger();
builder.Logging.ClearProviders();
builder.Logging.AddSerilog(logger);

var app = builder.Build();

var lVerSwagger = Convert.ToBoolean(builder.Configuration.GetSection("CliSwagger")["Visible"]);

// Configure the HTTP request pipeline.
if (lVerSwagger)
{
    app.UseSwagger();
    app.UseSwaggerUI();
    //app.UseSwaggerUI(c =>
    //{
    //    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MyAppAPI");
    //    c.OAuthClientId(builder.Configuration["Jwt:ClientId"]);
    //    c.OAuthClientSecret(builder.Configuration["Jwt:ClientSecret"]);
    //    c.OAuthRealm(builder.Configuration["Jwt:Realm"]);
    //    c.OAuthAppName("KEYCLOAK");
    //});
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseCors(x => x.AllowAnyHeader()
 .AllowAnyMethod()
 .AllowAnyOrigin());

app.UseAuthentication();

app.UseAuthorization();


app.MapControllers();


app.UseCors();

app.Run();


