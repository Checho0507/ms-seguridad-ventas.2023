import { /* inject, */ BindingScope, injectable} from '@loopback/core';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5')

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadService {
  constructor(/* Add @inject to inject parameters */) { }

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

  cifrarClave(cadena: string): string {
    const cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }
}
