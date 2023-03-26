import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import {RolMenuRepository} from '../repositories';

@injectable({scope: BindingScope.TRANSIENT})
export class AuthService {
  constructor(
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository
  ) { }

  async verificarPermisoDeUsuarioPorRol(idRol: string, idMenu: string, accion: string): Promise<UserProfile | undefined> {
    const permiso = await this.repositorioRolMenu.findOne({
      where: {
        rolId: idRol,
        menuId: idMenu
      }
    });
    let continuar = false;
    if (permiso) {
      switch (accion) {
        case "guardar":
          continuar = permiso.guardar;
          break;
        case "editar":
          continuar = permiso.editar;
          break;
        case "listar":
          continuar = permiso.listar;
          break;
        case "eliminar":
          continuar = permiso.eliminar;
          break;
        case "descargar":
          continuar = permiso.descargar;
          break;

        default:
          throw new HttpErrors[401]("No es posible ejecutar la acción porque no existe")
      }
      if (continuar) {
        const perfil: UserProfile = Object.assign({
          permitido: "OK"
        });
        return perfil;
      } else {
        return undefined;
      }
    } else {
      throw new HttpErrors[401]("No es posible ejecutar la acción por falta de permisos");
    }
  }
}
