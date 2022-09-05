using Paseto;
using Paseto.Builder;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var version = ProtocolVersion.V4;
var purpose = Purpose.Local;
var pasetoKey = new PasetoBuilder().Use(version, purpose)
                                   .GenerateSymmetricKey();

app.MapPost("/get-token/{name}", (string name) =>
{
    return new PasetoBuilder().Use(version, purpose)
                               .WithKey(pasetoKey)
                               .AddClaim("name", name)
                               .Audience("paseto.io")
                               .Issuer("localhost:5050")
                               .Subject("PASETO-DEMO")
                               .NotBefore(DateTime.UtcNow)
                               .IssuedAt(DateTime.UtcNow)
                               .Expiration(DateTime.UtcNow.AddHours(1))
                               .TokenIdentifier("123456ABCD")
                               .AddFooter("arbitrary-string-that-isn't-json")
                               .Encode();
});

app.MapGet("/decode/{token}", (string token) =>
{
    var validationParameters = new PasetoTokenValidationParameters
    {
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidateLifetime = true,
        ValidateSubject = true,
        ValidAudience = "paseto.io",
        ValidIssuer = "localhost:5050",
        ValidSubject = "PASETO-DEMO",
    };

    var response = new PasetoBuilder().Use(version, purpose)
                              .WithKey(pasetoKey)
                              .Decode(token, validationParameters);
    if (!response.IsValid)
        return Results.BadRequest($"Invalid access token: {response.Exception}");

    return Results.Ok(response.Paseto.Payload);
});

app.Run();