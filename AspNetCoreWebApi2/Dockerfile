FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 90

ENV ASPNETCORE_URLS=http://+:90

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src

COPY ["AspNetCoreWebApi2.csproj", "AspNetCoreWebApi2/"]
RUN dotnet restore "AspNetCoreWebApi2/AspNetCoreWebApi2.csproj"

#COPY *.csproj .
#RUN dotnet restore

COPY . ./AspNetCoreWebApi2/
WORKDIR "/src/AspNetCoreWebApi2"
RUN dotnet build "AspNetCoreWebApi2.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AspNetCoreWebApi2.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AspNetCoreWebApi2.dll"]
