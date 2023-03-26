import {AuthenticationBindings, AuthenticationMetadata, AuthenticationStrategy} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {RolMenuRepository} from '../repositories';
import {AuthService, SeguridadService} from '../services';

export class AuthStrategy implements AuthenticationStrategy {
  name = 'auth';

  constructor(
    @service(SeguridadService)
    private servicioSeguridad: SeguridadService,
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata[],
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository,
    @service(AuthService)
    private servicioAuth: AuthService
  ) { }

  /**
   * Autenticación d eun usuario frente a una acción en la base de datos
   * @param request la solicitud con el token
   * @returns el perfil de usuario, undefined cuando no tiene permiso o un httpError
   */
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    const token = parseBearerToken(request);
    if (token) {
      const idRol = this.servicioSeguridad.obtenerRolDesdeToken(token);
      const idMenu: string = this.metadata[0].options![0];
      const accion: string = this.metadata[0].options![1];

      try {
        let res = await this.servicioAuth.verificarPermisoDeUsuarioPorRol(idRol, idMenu, accion);
        return res;
      } catch (e) {
        throw e;
      }

    } else {
      throw new HttpErrors[401]("No es posible ejecutar la acción por falta de un token");
    }

  }
}
