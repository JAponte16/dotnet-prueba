using sico.data;
using sico.models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Npgsql;
using System.Data;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using sico.clases;
using MimeKit;
using System.Xml.Linq;
using System.Linq;
using System.Reflection.PortableExecutable;
using Microsoft.EntityFrameworkCore;
using sico.validadores;
using NS = Newtonsoft.Json;
using sico_master.Clases;
using Finbuckle.MultiTenant.Abstractions;


namespace sico_admon.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AdmonController : ControllerBase, IDisposable
    {
        private readonly SicoDbContext _DB;
        public IConfiguration _CONF;
        private readonly ILogger<AdmonController> _LOGGER;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITenantInfo _tenantInfo;

        public AdmonController(SicoDbContext __db, IConfiguration __conf, ILogger<AdmonController> __logger, IHttpContextAccessor httpContextAccessor)
        {
            this._DB = __db;
            this._CONF = __conf;
            this._LOGGER = __logger;
            _httpContextAccessor = httpContextAccessor;
        }

        public void Dispose()
        {
            _DB?.Dispose();
        }

        [Route("estado")]
        [HttpGet]
        public async Task<ActionResult> estado()
        {
            return Ok();
        }

        [Route("iniSesion")]
        [HttpPost]
        public async Task<ActionResult<ResponseAll>> iniSesion([FromBody] System.Object __data)
        {
            int? _idUsuario = 0;
            int? _idPersona = 0;
            bool? _esSystemAdmin = false;
            bool? _esSuperAdmin = false;
            bool? _esAdministrador = false;
            bool? _esPresidente = false;
            bool? _esVicepresidente = false;
            bool? _esDirector = false;
            bool? _esGerente = false;
            bool? _esSupervisor = false;
            bool? _esCoordinador = false;
            bool? _esAnalista = false;
            bool? _esAuditor = false;
            bool? _esCliente = false;
            bool? _esInvitado = false;
            bool? _esLector = false;
            bool? _esEscritor = false;
            bool? _esSupresor = false;
            bool? _esPersona = false;
            bool? _esUsuario = false;
            string _nombreUsuario = "";
            string _nombreRol = "";
            string _avatar = "";

            try
            {
                #region Iniciar Session
                string _media = "";
                var _minExpToken = Convert.ToInt32(_DB.AdmParametros.Where(x => x.NomParametro == "HORAS_EXPIRACION_TOKEN").FirstOrDefault().ValorParametro);
                var _data = JsonConvert.DeserializeObject<dynamic>(__data.ToString());

                string _usr = _data.usuario.ToString();
                string _password = _data.password.ToString();

                _idUsuario = (_DB.AdmUsuarios.Where(x => x.UsuarioLogin == _usr && x.ContrasennaLogin == _password && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).Count() > 0)
                        ? _DB.AdmUsuarios.Where(x => x.UsuarioLogin == _usr && x.ContrasennaLogin == _password && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).FirstOrDefault().Id
                        : 0;

                if (_idUsuario != null && _idUsuario > 0)
                {
                    _media = _DB.AdmParametros.Where(x => x.NomParametro == "SIIC_NG_MEDIA").FirstOrDefault().ValorParametro;

                    AdmUsuario _usuario = _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault();
                    AdmRol _rol = _DB.AdmRols.Where(x => x.Id == _usuario.CodRol).FirstOrDefault();
                    _esSystemAdmin = _rol.EsSystemadmin;
                    _esSuperAdmin = _rol.EsSuperadmin;
                    _esAdministrador = _rol.EsAdministrador;
                    _esPresidente = _rol.EsPresidente;
                    _esVicepresidente = _rol.EsVicepresidente;
                    _esDirector = _rol.EsDirector;
                    _esGerente = _rol.EsGerente;
                    _esCoordinador = _rol.EsCoordinador;
                    _esSupervisor = _rol.EsSupervisor;
                    _esAnalista = _rol.EsAnalista;
                    _esAuditor = _rol.EsAuditor;
                    _esCliente = _rol.EsCliente;
                    _esInvitado = _rol.EsInvitado;
                    _esLector = _rol.EsLector;
                    _esEscritor = _rol.EsEscritor;
                    _esSupresor = _rol.EsSupresor;
                    _esUsuario = _idUsuario > 0;
                    _nombreUsuario = string.Format("{0} {1}", _usuario.PrimerNombre, _usuario.PrimerApellido);
                    _nombreRol = _rol.NomRol;
                    _avatar = _usuario.PathFoto == null || _usuario.PathFoto == "" ? _media + "/nodo_a1/users/avatar/avatar-generico.png" : _media + _usuario.PathFoto;

                    _usuario.FechaUltimoIngreso = DateTime.Now;

                    var local = _DB.Set<AdmUsuario>().Local
                                    .FirstOrDefault(entry => entry.Id.Equals(_idUsuario));

                    if (local != null)
                        _DB.Entry(local).State = EntityState.Detached;

                    _DB.Entry(_usuario).State = EntityState.Modified;
                    _DB.SaveChanges();

                }
                else
                {
                    _idPersona = (_DB.CrmPersonas.Where(x => x.UsuarioLogin == _usr && x.ContrasennaLogin == _password && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).Count() > 0)
                       ? _DB.CrmPersonas.Where(x => x.UsuarioLogin == _usr && x.ContrasennaLogin == _password && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).FirstOrDefault().Id
                       : 0;

                    bool _loginOn = _idPersona > 0;

                    if (_idPersona == null || _idPersona == 0)
                    {
                        _idPersona = (_DB.CrmPersonas.Where(x => x.UsuarioLogin == _usr && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).Count() > 0)
                          ? _DB.CrmPersonas.Where(x => x.UsuarioLogin == _usr && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).FirstOrDefault().Id
                          : 0;
                    }


                    _loginOn = _loginOn;


                    if (_loginOn && _idPersona != null && _idPersona > 0)
                    {
                        _media = _DB.AdmParametros.Where(x => x.NomParametro == "SIIC_NG_MEDIA").FirstOrDefault().ValorParametro;
                        var _envVar = _DB.AdmParametros.Where(x => x.NomParametro == "ENVIRONMENT_VAR").FirstOrDefault().ValorParametro;
                        var _envVarJson = JsonConvert.DeserializeObject<List<UItem>>(_envVar);
                        var _bloqueoSesionOn = Convert.ToBoolean(_envVarJson.Where(x => x.Name == "adm_sesion_bloqueo_on").FirstOrDefault().Value);

                        bool _bloqueo = _bloqueoSesionOn;

                        try { _bloqueo = _bloqueoSesionOn && Convert.ToBoolean(_data.bloqueo); } catch (Exception ex) { _bloqueo = _bloqueoSesionOn; }


                        _esPersona = true;
                        CrmPersona _persona = _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault();
                        _nombreRol = "Cliente";
                        _nombreUsuario = string.Format("{0} {1}", _persona.PrimerNombre, _persona.PrimerApellido);
                        _avatar = _media + "/nodo_a1/users/avatar/avatar-generico.png";

                        _persona.EsBloqueado = _bloqueo;

                        var local = _DB.Set<CrmPersona>().Local
                                     .FirstOrDefault(entry => entry.Id.Equals(_idPersona));

                        if (local != null)
                            _DB.Entry(local).State = EntityState.Detached;

                        _DB.Entry(_persona).State = EntityState.Modified;
                        _DB.SaveChanges();
                    }
                    else
                    {
                        return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                    }
                }

                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);


                TokenManager _tokenManager = new TokenManager(_idUsuario, _idPersona, _esSystemAdmin, _esSuperAdmin, _esAdministrador, _esPresidente, _esVicepresidente, _esDirector,
                    _esGerente, _esCoordinador, _esSupervisor, _esAnalista, _esAuditor, _esCliente, _esInvitado, _esLector, _esEscritor,
                    _esSupresor, _esPersona, _esUsuario, _nombreUsuario, _nombreRol, _avatar, _secretKey, 180);

                var _jwtToken = _tokenManager.IssuingJWT();

                int _statusCode = _jwtToken == null || !_jwtToken.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _jwtToken });

                #endregion
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "iniSesion", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtEstadoSesion")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtEstadoSesion()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                int _statusCode = _idPersona == 0 && _idUsuario == 0 ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = null });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "obtEstadoSesion", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("cerrarSesion")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> cerrarSesion()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                if (_idPersona != null && _idPersona > 0)
                {
                    CrmPersona _persona = _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault();
                    _persona.EsBloqueado = false;

                    var local = _DB.Set<CrmPersona>().Local
                                 .FirstOrDefault(entry => entry.Id.Equals(_idPersona));

                    if (local != null)
                        _DB.Entry(local).State = EntityState.Detached;

                    _DB.Entry(_persona).State = EntityState.Modified;
                    _DB.SaveChanges();
                }

                int _statusCode = _idPersona == 0 && _idUsuario == 0 ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = null });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "obtEstadoSesion", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtRecuperarPass")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtRecuperarPass(string __email)
        {
            int? _idUsuario;
            int? _idPersona;
            try
            {
                _idPersona = (_DB.CrmPersonas.Where(x => x.Email == __email && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).Count() > 0)
                         ? _DB.CrmPersonas.Where(x => x.Email == __email && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).FirstOrDefault().Id
                         : 0;

                _idUsuario = (_DB.AdmUsuarios.Where(x => x.Email == __email && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).Count() > 0)
                        ? _DB.AdmUsuarios.Where(x => x.Email == __email && x.EsActivo == true && x.EsEliminado == false && x.EsBloqueado == false).FirstOrDefault().Id
                        : 0;

                if ((_idUsuario == null
                    || _idUsuario == 0)
                    && (_idPersona == null
                    || _idPersona == 0))
                    return BadRequest(new ResponseAll { code = 400, message = SystemMessage.BadRequest, data = null });

                bool _esUsuario = _idUsuario == null || _idUsuario == 0 ? false : true;
                string _contrasenna = _esUsuario ?
                    _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault().ContrasennaLogin
                    : _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault().ContrasennaLogin;

                string _nombre = _esUsuario ?
                    string.Format("{0} {1} {2} {3}"
                    , _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault().PrimerNombre
                    , _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault().SegundoNombre
                    , _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault().PrimerApellido
                    , _DB.AdmUsuarios.Where(x => x.Id == _idUsuario).FirstOrDefault().SegundoApellido)
                    : string.Format("{0} {1} {2} {3}"
                    , _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault().PrimerNombre
                    , _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault().SegundoNombre
                    , _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault().PrimerApellido
                    , _DB.CrmPersonas.Where(x => x.Id == _idPersona).FirstOrDefault().SegundoApellido);

                List<SystemSmtpServer> _servers = JsonConvert.DeserializeObject<List<SystemSmtpServer>>(_DB.AdmParametros.Where(x => x.NomParametro == "SMTP_SERVER").FirstOrDefault().ValorParametro);
                List<SystemFromTo> _from = JsonConvert.DeserializeObject<List<SystemFromTo>>(_DB.AdmParametros.Where(x => x.NomParametro == "SMTP_SENDER").FirstOrDefault().ValorParametro);
                SystemFromTo _to = new SystemFromTo { name = _nombre, email = __email };
                List<SystemFromTo> _tos = new List<SystemFromTo>();
                List<SystemFromTo> _co = new List<SystemFromTo>();
                List<SystemFromTo> _cco = new List<SystemFromTo>();

                _tos.Add(_to);
                string _subject = "SIIC NG - Recuperación de contraseña";
                var _builder = new BodyBuilder();
                string _images = _DB.AdmParametros.Where(x => x.NomParametro == "SIIC_NG_MEDIA").FirstOrDefault().ValorParametro;
                string _body = _DB.EngEmailTemplates.Where(x => x.Keyword == "GET_PASSWORD").FirstOrDefault().Body;
                _body = _body.Replace("[SIIC_NG_IMAGES]", _images);
                _body = _body.Replace("[PASSWORD]", _contrasenna);

                _builder.HtmlBody = _body;

                (new Mensajeria(_servers)).SendMail(_servers.FirstOrDefault().keyword, _from, _tos, _co, _cco, _subject, _builder);


                return Ok(new ResponseAll { code = 200, message = "Por favor revise su correo...", data = null });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "obtContrasenna", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("getEncode")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> getEncode(string __data)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                var _dataResponse = Seguridad.getEncode(__data);
                int _statusCode = _dataResponse == null || !_dataResponse.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _dataResponse });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "getEncode", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

       
        [Route("getDecode")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> getDecode(string __data)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                var _dataResponse = Seguridad.getDecode(__data);
                int _statusCode = _dataResponse == null || !_dataResponse.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _dataResponse });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Authenticator", "getDecode", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtMenu")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtMenu()
        {
            try
            {

                #region Decodificar Token
                var rol = new KeycloakTokenManager(_httpContextAccessor).getRol();
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                #region Traer de BD Textos

                System.Object _json = null;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select public.adm_menu_by_rol_get('{0}',{1})", rol, tenant), _conn))
                    {
                        _json = _command.ExecuteScalar().ToString();
                        _conn.Close();
                    }
                }

                #endregion

                int lStatusCode = _json == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = _json.ToString() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtMenu", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtTextosNoPagina")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtTextosNoPagina(int __codIdioma)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {

                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                #region Traer de BD Textos

                System.Object _json = null;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_texto_get({0})", __codIdioma), _conn))
                    {
                        _json = _command.ExecuteScalar().ToString();
                        _conn.Close();
                    }
                }

                //List<UCerExamenPersona> _consulta = JsonConvert.DeserializeObject<List<UCerExamenPersona>>(_json.ToString());
                #endregion

                int lStatusCode = _json == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = _json.ToString() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtTextosNoPagina", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtLoginData")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtLoginData(int __codIdioma)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {

                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                #region Traer de BD Textos

                System.Object _json = null;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_login_data_get({0})", __codIdioma), _conn))
                    {
                        _json = _command.ExecuteScalar().ToString();
                        _conn.Close();
                    }
                }

                //List<UCerExamenPersona> _consulta = JsonConvert.DeserializeObject<List<UCerExamenPersona>>(_json.ToString());
                #endregion

                int lStatusCode = _json == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = _json.ToString() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtLoginData", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtParametros")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtParametros()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                var _parametros = _DB.AdmParametros
                        .Distinct();

                int _statusCode = _parametros == null || !_parametros.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _parametros.ToArray() });

            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtParametros", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtTenant")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtTenant()
        {
            try
            {
                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                var _tenant = _DB.AdmTenants.Where(t => t.Id == tenant);

                int _statusCode = _tenant == null || !_tenant.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _tenant.ToArray() });

            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtTenant", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("modParametro")]
        [HttpPost]
        public async Task<ActionResult<ResponseAll>> modParametro([FromBody] System.Object __data)
        {
            string _errorMsg = "";

            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                //if (_idUsuario == 0)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });

                UItem _datos = NS.JsonConvert.DeserializeObject<UItem>(__data.ToString());

                var _parametro = _DB.AdmParametros.Where(x => x.NomParametro == _datos.Name).FirstOrDefault();

                _parametro.ValorParametro = _datos.Value;

                var local = _DB.Set<AdmRol>().Local.FirstOrDefault(entry => entry.Id.Equals(_parametro.Id));

                if (local != null)
                    _DB.Entry(local).State = EntityState.Detached;

                _DB.Entry(_parametro).State = EntityState.Modified;
                _DB.SaveChanges();

                return Ok(new ResponseAll { code = 200, message = SystemMessage.OK, data = _parametro });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "modParametro", ex.Message));
                _errorMsg += "\n:::Error general:::" + ex.Message;
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = _errorMsg });
            }
        }

        [Authorize]
        [Route("obtListas")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtListas()
        {

            try
            {
                #region Decodificar Token
                var rol = new KeycloakTokenManager(_httpContextAccessor).getRol();
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                List<Listas> _listas = new List<Listas>();
                DataTable? _table = new DataTable();
                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));
                NpgsqlDataReader lReader;
                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand lCommand = new NpgsqlCommand(string.Format("select adm_trae_listas({0})", tenant), _conn))
                    {
                        lReader = lCommand.ExecuteReader();
                        _table.Load(lReader);

                        lReader.Close();
                        _conn.Close();

                    }
                }

                foreach (DataRow _row in _table.Rows)
                {
                    Listas _lista = new Listas();
                    _lista.ind = Convert.ToInt32(((object[])_row[0])[0]);
                    _lista.id = Convert.ToInt32(((object[])_row[0])[1]);
                    _lista.nombre = ((object[])_row[0])[2].ToString();
                    _lista.cod_padre = Convert.ToInt32(((object[])_row[0])[3]);
                    _listas.Add(_lista);
                }

                var _dataResponse = _listas.ToArray();
                int _statusCode = _dataResponse == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _dataResponse });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtListas", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtLista")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtLista(int __indice)
        {
            try
            {
                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                List<Lista> _listas = new List<Lista>();
                DataTable _table = new DataTable();
                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));
                NpgsqlDataReader lReader;
                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand lCommand = new NpgsqlCommand(string.Format("select adm_trae_lista({0},{1})", __indice, tenant), _conn))
                    {
                        lReader = lCommand.ExecuteReader();
                        _table.Load(lReader);

                        lReader.Close();
                        _conn.Close();

                    }
                }

                foreach (DataRow _row in _table.Rows)
                {
                    Lista _lista = new Lista();
                    _lista.id = Convert.ToInt32(((object[])_row[0])[0]);
                    _lista.nombre = ((object[])_row[0])[1].ToString();
                    _lista.cod_padre = Convert.ToInt32(((object[])_row[0])[2]);
                    _listas.Add(_lista);
                }

                var _dataResponse = _listas;
                int _statusCode = _dataResponse == null || !_dataResponse.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _dataResponse });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtListas", ex.Message));
                //(new Observabilidad(_DB)).setLog(_idUsuario, _idPersona, string.Format("{0}.{1}=>{2}","Administration", "obtListas", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtListaPorPadre")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtListaPorPadre(int __indice, int __idPadre)
        {
            try
            {

                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion


                List<Lista> _listas = new List<Lista>();
                DataTable _table = new DataTable();
                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));
                NpgsqlDataReader lReader;
                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand lCommand = new NpgsqlCommand(string.Format("select adm_trae_lista({0}, {1}, {2})", __indice, __idPadre, tenant), _conn))
                    {
                        lReader = lCommand.ExecuteReader();
                        _table.Load(lReader);

                        lReader.Close();
                        _conn.Close();

                    }
                }

                foreach (DataRow _row in _table.Rows)
                {
                    Lista _lista = new Lista();
                    _lista.id = Convert.ToInt32(((object[])_row[0])[0]);
                    _lista.nombre = ((object[])_row[0])[1].ToString();
                    _lista.cod_padre = Convert.ToInt32(((object[])_row[0])[2]);
                    _listas.Add(_lista);
                }

                var _dataResponse = _listas;
                int _statusCode = _dataResponse == null || !_dataResponse.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = _dataResponse });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtListasPorPadre", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtFormDinamico")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtFormDinamico(string __dynForm, int? __id = 0)
        {
   
            try
            {
                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                #region Traer de BD Items Dynamic Forms

                System.Object _json = null;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_dynamic_form_get('{0}',{1}, {2})", __dynForm, __id, tenant), _conn))
                    {
                        _json = _command.ExecuteScalar().ToString();
                        _conn.Close();
                    }
                }

                #endregion

                int lStatusCode = _json == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = _json.ToString() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "obtFormDinamico", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("modFormDinamico")]
        [HttpPost]
        public async Task<ActionResult<ResponseAll>> modFormDinamico([FromBody] System.Object __data)
        {
      
            try
            {
                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                #region Traer de BD Items Dynamic Forms

                int? _response = 0;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_dynamic_form_set('{0}',{1})", __data, tenant), _conn))
                    {
                        _response = Convert.ToInt32(_command.ExecuteScalar());
                        _conn.Close();
                    }
                }

                #endregion

                int lStatusCode = (_response == null || _response == 0) ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = (_response != null && _response > 0) });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "modFormDinamico", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("obtRoles")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtRoles()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                //var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                //string _secretKey = Seguridad.getDecode(_jwt.Key);
                //TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                //if (!_tokenRenew.IsValid)
                //    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                //_idUsuario = _tokenRenew.IdUsuario;
                //_idPersona = _tokenRenew.IdPersona;
                #endregion

                var _roles = _DB.AdmRols
                        .Where(x => x.EsEliminado == false && x.Id > 1)
                        .Distinct();

                int _statusCode = _roles == null || !_roles.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _roles.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtRoles", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtRol")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtRol(int __id)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _roles = _DB.AdmRols
                        .Where(x => x.Id == __id && x.EsEliminado == false)
                        .Distinct();

                int _statusCode = _roles == null || !_roles.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _roles.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtRol", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuarios")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuarios()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.EsEliminado == false && x.Id > 1)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuarios", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuariosAdm")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuariosAdm()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.EsEliminado == false && x.Id > 1 && x.CodRolNavigation.EsSuperadmin == true)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuarios", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuariosCoor")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuariosCoor()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.EsEliminado == false && x.Id > 1 && x.CodRolNavigation.EsCoordinador == true)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuarios", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuariosSu")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuariosSu()
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.EsEliminado == false && x.Id > 1 && x.CodRolNavigation.EsSupervisor == true)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuarios", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuario")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuario(int __id)
        {
            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.Id == __id && x.EsEliminado == false)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuario", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("obtUsuarioPorULogin")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtUsuarioPorULogin(string __usuarioLoging)
        {
            try
            {
                #region Decodificar Token

                #endregion

                var _usuarios = _DB.AdmUsuarios
                        .Include(x => x.CodRolNavigation)
                        .Where(x => x.Email == __usuarioLoging && x.EsEliminado == false)
                        .Distinct();

                int _statusCode = _usuarios == null || !_usuarios.Any() ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string _message = _statusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = _statusCode, message = _message, data = await _usuarios.ToArrayAsync() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "obtUsuarioPorULogin", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }

        }

        [Authorize]
        [Route("modUsuarios")]
        [HttpPost]
        public async Task<ActionResult<ResponseAll>> modUsuarios([FromBody] System.Object __data)
        {
            string _errorMsg = "";

            int _idUsuario = 0;
            int _idPersona = 0;
            try
            {
                #region Decodificar Token
                var _jwt = _CONF.GetSection("Jwt").Get<Jwt>();
                string _secretKey = Seguridad.getDecode(_jwt.Key);
                TokenRenew _tokenRenew = new TokenRenew(HttpContext.Request, _secretKey);
                if (!_tokenRenew.IsValid)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });
                _idUsuario = _tokenRenew.IdUsuario;
                _idPersona = _tokenRenew.IdPersona;
                #endregion

                if (_idUsuario == 0)
                    return Unauthorized(new ResponseAll { code = 401, message = SystemMessage.Unauthorized, data = null });

                List<AdmUsuario> _datos = JsonConvert.DeserializeObject<List<AdmUsuario>>(__data.ToString());

                foreach (AdmUsuario _dato in _datos)
                {
                    int _idUser = 0;
                    int _idRol = 0;
                    string _indPaisPhones = "57";
                    string _indCiudadPhones = "";
                    string _prefijoPhones = "3";
                    int? _lengthPhones = 10;

                    if (_dato.CodRolNavigation != null && _dato.CodRolNavigation.Id >= 0)
                    {
                        try
                        {
                            AdmRol _rol = new AdmRol();

                            _rol.NomRol = Formato.ToUpperFirst(_dato.CodRolNavigation.NomRol);
                            _rol.EsSuperadmin = _dato.CodRolNavigation.EsSuperadmin;
                            _rol.EsCoordinador = _dato.CodRolNavigation.EsCoordinador;
                            _rol.EsSupervisor = _dato.CodRolNavigation.EsSupervisor;
                            _rol.EsActivo = _dato.CodRolNavigation.EsActivo;
                            _rol.EsEliminado = _dato.CodRolNavigation.EsEliminado;
                            if (_dato.CodRolNavigation.Id == 0)
                            {
                                var _object = _DB.AdmRols
                                    .Where(x => x.NomRol == _rol.NomRol
                                        && x.EsActivo == true)
                                    .FirstOrDefault();
                                if (_object == null)
                                {
                                    _idRol = _DB.AdmRols
                                        .Where(x => x.Id == _DB.AdmRols
                                        .Max(y => y.Id)).First().Id + 1;
                                }
                                else
                                {
                                    _idRol = _object.Id;
                                }
                                _rol.Id = _idRol;
                            }
                            else
                            {
                                _rol.Id = _dato.CodRolNavigation.Id;
                            }

                            if (_rol.Id > 0)
                            {
                                if (_DB.AdmRols.Find(_rol.Id) != null)
                                {
                                    _rol.FCreacion = _DB.AdmRols.Find(_rol.Id).FCreacion;
                                    _rol.FModificacion = DateTime.Now;

                                    var local = _DB.Set<AdmRol>().Local
                                                    .FirstOrDefault(entry => entry.Id.Equals(_rol.Id));

                                    if (local != null)
                                        _DB.Entry(local).State = EntityState.Detached;

                                    _DB.Entry(_rol).State = EntityState.Modified;
                                    _DB.SaveChanges();
                                }
                                else
                                {
                                    _rol.FCreacion = DateTime.Now;
                                    _rol.FModificacion = DateTime.Now;
                                    _DB.AdmRols.Add(_rol);
                                    _DB.SaveChanges();
                                }
                                _errorMsg += string.Format("\nEscritura en Rol({0}) exitosa...", _rol.Id);
                            }
                        }
                        catch (Exception ex)
                        {
                            _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "modUsuarios", ex.Message));
                            _errorMsg += string.Format("\nError al escribir en Rol({0}):::{1}", _dato.CodRol, ex.Message);
                        }
                    }
                    try
                    {
                        AdmUsuario _usuario = new AdmUsuario();
                        if (_dato.CodRol == 0)
                        {
                            _usuario.CodRol = _idRol;
                        }
                        else
                        {
                            _usuario.CodRol = _dato.CodRol;
                        }


                        var _ciudad = _dato.CodCiudad != null ? _DB.AdmCiudads.Where(x => x.Id == _dato.CodCiudad).FirstOrDefault() : null;
                        var _depto = _ciudad != null ? _DB.AdmDepartamentos.Where(x => x.Id == _ciudad.CodDepartamento).FirstOrDefault() : null;
                        var _pais = _depto != null ? _DB.AdmPais.Where(x => x.Id == _depto.CodPais).FirstOrDefault() : null;

                        if (_pais != null && _ciudad != null)
                        {
                            _indPaisPhones = _pais.IndMovil.Replace(" ", "");
                            _prefijoPhones = _pais.PrefijoMovil.Replace(" ", "");
                            _lengthPhones = _pais.LMovil;
                            _indCiudadPhones = _ciudad.IndMovil.Replace(" ", "");

                        }
                        _usuario.Celular = _dato.Celular == null ? null : Formato.ToPhones(_indPaisPhones.Trim(), _indCiudadPhones.Trim(), _prefijoPhones.Trim(), _lengthPhones, _dato.Celular.Trim());
                        _usuario.CodCiudad = _dato.CodCiudad != null ? _dato.CodCiudad : 1;
                        _usuario.CodIdioma = _dato.CodIdioma != null ? _dato.CodIdioma : 1;
                        _usuario.CodTipoIdentificacion = _dato.CodTipoIdentificacion != 0 ? _dato.CodTipoIdentificacion : null;
                        _usuario.Email = _dato.Email;
                        _usuario.FechaRegistro = _dato.FechaRegistro;
                        _usuario.FechaUltimoIngreso = _dato.FechaUltimoIngreso;
                        _usuario.Identificacion = _dato.Identificacion;
                        _usuario.PrimerApellido = Formato.ToUpperFirst(_dato.PrimerApellido);
                        _usuario.PrimerNombre = Formato.ToUpperFirst(_dato.PrimerNombre);
                        _usuario.SegundoApellido = Formato.ToUpperFirst(_dato.SegundoApellido);
                        _usuario.SegundoNombre = Formato.ToUpperFirst(_dato.SegundoNombre);
                        _usuario.CodCompannia = _dato.CodCompannia != 0 ? _dato.CodCompannia : null;
                        _usuario.UsuarioLogin = _dato.UsuarioLogin != null ? _dato.UsuarioLogin : _dato.Identificacion;
                        _usuario.ContrasennaLogin = _dato.ContrasennaLogin != null ? _dato.ContrasennaLogin : _dato.Identificacion;
                        _usuario.PathFirma = _dato.PathFirma;
                        _usuario.PathFoto = _dato.PathFoto;
                        _usuario.ToMeet = _dato.ToMeet != null ? _dato.ToMeet : _dato.Email;
                        _usuario.EsEliminado = _dato.EsEliminado != null ? _dato.EsEliminado : false;
                        _usuario.EsBloqueado = _dato.EsBloqueado != null ? _dato.EsBloqueado : false;
                        _usuario.EsActivo = _dato.EsActivo != null ? _dato.EsActivo : true;

                        if (_pais != null && _ciudad != null)
                        {
                            _indPaisPhones = _pais.IndFijo;
                            _prefijoPhones = _pais.PrefijoFijo;
                            _lengthPhones = _pais.LFijo;
                            _indCiudadPhones = _ciudad.IndFijo;
                        }

                        _usuario.OtrosTelefonos = _dato.OtrosTelefonos == null ? null : Formato.ToPhones(_indPaisPhones.Trim(), _indCiudadPhones.Trim(), _prefijoPhones.Trim(), _lengthPhones, _dato.OtrosTelefonos.Trim());


                        if (_dato.Id == 0)
                        {
                            var _object = _DB.AdmUsuarios
                                    .Where(x => x.Identificacion == _usuario.Identificacion
                                        && x.CodTipoIdentificacion == _usuario.CodTipoIdentificacion
                                        && x.EsActivo == true
                                        && x.EsEliminado == false)
                                    .FirstOrDefault();
                            if (_object == null)
                            {
                                _idUser = _DB.AdmUsuarios
                                     .Where(x => x.Id == _DB.AdmUsuarios
                                     .Max(y => y.Id)).First().Id + 1;
                            }
                            else
                            {
                                _idUser = _object.Id;
                            }
                            _usuario.Id = _idUser;
                        }
                        else
                        {
                            _usuario.Id = _dato.Id;
                        }

                        if (_usuario.CodRol > 0 && _usuario.Id > 0)
                        {
                            if (_DB.AdmUsuarios.Find(_usuario.Id) != null)
                            {
                                _usuario.FCreacion = _DB.AdmUsuarios.Find(_usuario.Id).FCreacion;
                                _usuario.FModificacion = DateTime.Now;

                                var local = _DB.Set<AdmUsuario>().Local
                                               .FirstOrDefault(entry => entry.Id.Equals(_usuario.Id));

                                if (local != null)
                                    _DB.Entry(local).State = EntityState.Detached;

                                _DB.Entry(_usuario).State = EntityState.Modified;
                                _DB.SaveChanges();

                            }
                            else
                            {
                                _usuario.FCreacion = DateTime.Now;
                                _usuario.FModificacion = DateTime.Now;
                                _usuario.FechaRegistro = DateTime.Now;
                                _DB.AdmUsuarios.Add(_usuario);
                                _DB.SaveChanges();
                            }
                            _errorMsg += string.Format("\n:::Escritura en Usuario({0}) exitosa...", _dato.Id);
                        }
                        else
                        {
                            _errorMsg += string.Format("\n:::Escritura en Usuario({0}) fallida ingrese un id_usuario que no sea -1 y un CodRol valido", _dato.Id);
                        }
                    }
                    catch (Exception ex)
                    {
                        _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "modUsuarios", ex.Message));
                        _errorMsg += string.Format("\n:::Error al escribir en Usuario({0}):::{1}", _dato.Id, ex.Message);
                    }
                }

                return Ok(new ResponseAll { code = 200, message = SystemMessage.OK, data = _errorMsg });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "User", "modUsuarios", ex.Message));
                _errorMsg += "\n:::Error general:::" + ex.Message;
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = _errorMsg });
            }
        }

        [Authorize]
        [Route("obtCuestionarios")]
        [HttpGet]
        public async Task<ActionResult<ResponseAll>> obtCuestionarios(string __keyword, int __codPrincipal)
        {
            try
            {

                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                #region Traer de BD Textos

                System.Object _json = null;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_cuestionario_get('{0}', {1}, {2})", __keyword, __codPrincipal, tenant), _conn))
                    {
                        _json = _command.ExecuteScalar().ToString();
                        _conn.Close();
                    }
                }

                #endregion

                int lStatusCode = _json == null ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = _json.ToString() });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Admon", "obtCuestionarios", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }

        [Authorize]
        [Route("modCuestionario")]
        [HttpPost]
        public async Task<ActionResult<ResponseAll>> modCuestionario([FromBody] System.Object __data)
        {
  
            try
            {
                #region Decodificar Token
                var tenant = int.Parse(new KeycloakTokenManager(_httpContextAccessor).getTenantId());
                #endregion

                #region Traer de BD Items Dynamic Forms

                int? _response = 0;

                string _cadenaConn = Seguridad.getDecode(_CONF.GetConnectionString("Postgres_Db"));

                using (NpgsqlConnection _conn = new NpgsqlConnection(_cadenaConn))
                {
                    _conn.Open();
                    using (NpgsqlCommand _command = new NpgsqlCommand(string.Format("select adm_cuestionario_set('{0}',{1})", __data, tenant), _conn))
                    {
                        _response = Convert.ToInt32(_command.ExecuteScalar());
                        _conn.Close();
                    }
                }

                #endregion

                int lStatusCode = (_response == null || _response == 0) ? (int)HttpStatusCode.NoContent : (int)HttpStatusCode.OK;
                string lMessage = lStatusCode == (int)HttpStatusCode.OK ? SystemMessage.OK : SystemMessage.NoContent;
                return Ok(new ResponseAll { code = lStatusCode, message = lMessage, data = (_response != null && _response > 0) });
            }
            catch (Exception ex)
            {
                _LOGGER.LogInformation(string.Format("{0}.{1}=>{2}", "Administration", "modCuestionario", ex.Message));
                return NotFound(new ResponseAll { code = ex.HResult, message = SystemMessage.NotFound, data = ex.Message });
            }
        }
    }
}