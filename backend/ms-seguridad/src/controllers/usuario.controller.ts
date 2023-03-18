import {authenticate} from '@loopback/authentication';
import {service} from '@loopback/core';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where
} from '@loopback/repository';
import {
  del, get,
  getModelSchemaRef, HttpErrors, param, patch, post, put, requestBody,
  response
} from '@loopback/rest';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Login, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
import {SeguridadService} from '../services';

export class UsuarioController {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @service(SeguridadService)
    public servicioSeguridad: SeguridadService,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) { }

  @post('/usuario')
  @response(200, {
    description: 'Usuario model instance',
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}},
  })
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {
            title: 'NewUsuario',
            exclude: ['_id'],
          }),
        },
      },
    })
    usuario: Omit<Usuario, '_id'>,
  ): Promise<Usuario> {
    //Crear la clave
    const clave = this.servicioSeguridad.crearTextoAleatorio(10);
    //Cifrar la clave
    const claveCifrada = this.servicioSeguridad.cifrarTexo(clave);
    //Asignar clave cifrada a un usuario
    usuario.clave = claveCifrada;
    //Enviar correo
    return this.repositorioUsuario.create(usuario);
  }

  @get('/usuario/count')
  @response(200, {
    description: 'Usuario model count',
    content: {'application/json': {schema: CountSchema}},
  })
  async count(
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.repositorioUsuario.count(where);
  }

  @authenticate({
    strategy: "auth",
    options: [ConfiguracionSeguridad.menuUsuarioId, ConfiguracionSeguridad.listarAccion]
  })
  @get('/usuario')
  @response(200, {
    description: 'Array of Usuario model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(Usuario, {includeRelations: true}),
        },
      },
    },
  })
  async find(
    @param.filter(Usuario) filter?: Filter<Usuario>,
  ): Promise<Usuario[]> {
    return this.repositorioUsuario.find(filter);
  }

  @patch('/usuario')
  @response(200, {
    description: 'Usuario PATCH success count',
    content: {'application/json': {schema: CountSchema}},
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.repositorioUsuario.updateAll(usuario, where);
  }

  @get('/usuario/{id}')
  @response(200, {
    description: 'Usuario model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(Usuario, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.string('id') id: string,
    @param.filter(Usuario, {exclude: 'where'}) filter?: FilterExcludingWhere<Usuario>
  ): Promise<Usuario> {
    return this.repositorioUsuario.findById(id, filter);
  }

  @patch('/usuario/{id}')
  @response(204, {
    description: 'Usuario PATCH success',
  })
  async updateById(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
  ): Promise<void> {
    await this.repositorioUsuario.updateById(id, usuario);
  }

  @put('/usuario/{id}')
  @response(204, {
    description: 'Usuario PUT success',
  })
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() usuario: Usuario,
  ): Promise<void> {
    await this.repositorioUsuario.replaceById(id, usuario);
  }

  @del('/usuario/{id}')
  @response(204, {
    description: 'Usuario DELETE success',
  })
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.repositorioUsuario.deleteById(id);
  }

  /**
   * Métodos personalizados para la API
   */

  @post('/identificar-usuario')
  @response(200, {
    description: "Identificar un usuario por correo y clave",
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}}
  })
  async identificarUsuario(
    @requestBody({
      content: {'application/json': {schema: getModelSchemaRef(Credenciales)}}
    })
    credenciales: Credenciales
  ): Promise<object> {
    const usuario = await this.servicioSeguridad.identificarUsuario(credenciales);
    if (usuario) {
      const codigo2FA = this.servicioSeguridad.crearTextoAleatorio(5);
      const login: Login = new Login();
      login.usuarioId = usuario._id!;
      login.codigo2FA = codigo2FA;
      login.estadoCodigo2FA = false;
      login.token = "";
      login.estadoToken = false;
      await this.repositorioLogin.create(login);
      usuario.clave = "";
      // Notificar al usuario via correo electrónico
      return usuario;
    }
    return new HttpErrors[401]("Credenciales incorrectas");
  }

  @post('/verificar-2FA')
  @response(200, {
    description: "Validar un código de 2FA"
  })
  async verificarCodigo2FA(
    @requestBody({
      content: {'application/json': {schema: getModelSchemaRef(FactorDeAutenticacionPorCodigo)}}
    })
    credenciales: FactorDeAutenticacionPorCodigo
  ): Promise<object> {
    const usuario = await this.servicioSeguridad.validarCodigo2FA(credenciales);
    if (usuario) {
      const token = this.servicioSeguridad.crearToken(usuario);
      if (usuario) {
        usuario.clave = "";
        try {
          await this.repositorioUsuario.logins(usuario._id).patch(
            {
              estadoCodigo2FA: true,
              token: token
            }, {
            estadoCodigo2FA: false
          }
          );
        } catch (error) {
          console.log("No se ha almacenado el cambio de estado de token en la base de datos")
        }
        return {
          user: usuario,
          token: token
        };
      }
    }
    return new HttpErrors[401]("Código 2FA inválido para el usuario definido");
  }
}
