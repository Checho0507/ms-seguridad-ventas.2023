import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Credenciales, Usuario} from '../models';
import {UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5')

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository
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
}
