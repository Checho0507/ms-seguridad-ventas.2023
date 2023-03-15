import {AuthenticationStrategy} from '@loopback/authentication';
import {Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';

export class AuthStrategy implements AuthenticationStrategy {
  name = 'auth';

  constructor(

  ) { }

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    console.log("Ejecutando estrategia")

    return undefined;
  }
}
