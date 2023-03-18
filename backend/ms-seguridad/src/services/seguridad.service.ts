import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) { }

  /**
   * Crea un texto aleatorio de n caracteres
   * @returns texto aleatorio de n caracteres
   */
  crearTextoAleatorio(n: number): string {
    const password = generator.generate({
      length: n,
      numbers: true
    });
    return password;
  }

  /**
   * Cifra una cadena con método md5
   * @param cadena texto a cifrar
   * @returns cadena cifrada con md5
   */
  cifrarTexo(cadena: string): string {
    const cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * Se busca un usuario por sus credenciales de acceso
   * @param credenciales credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null> {
    const usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario;
  }

  /**
   * Valida un código de 2FA para un usuario
   * @param credenciales credecniale del usuario con el código del 2FA
   * @returns el registro de login o null
   */
  async validarCodigo2FA(credenciales: FactorDeAutenticacionPorCodigo): Promise<Usuario | null> {
    const login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales.usuarioId,
        codigo2FA: credenciales.codigo2FA,
        estadoCodigo2FA: false
      }
    });
    if (login) {
      const usuario = this.repositorioUsuario.findById(credenciales.usuarioId);
      return usuario;
    }
    return null;
  }

  /**
   * Generación de JWT
   * @param usuario información del usuario
   * @returns token
   */
  crearToken(usuario: Usuario): string {
    const datos = {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
      role: usuario.rolId,
      email: usuario.correo
    }
    const token = jwt.sign(datos, ConfiguracionSeguridad.claveJWT)
    return token;
  }

  /**
   * Valida y obtiene el rol de un token
   * @param tk el token
   * @returns el _id del rol
   */
  obtenerRolDesdeToken(tk: string): string {
    const obj = jwt.verify(tk, ConfiguracionSeguridad.claveJWT);
    return obj.role;
  }
}
