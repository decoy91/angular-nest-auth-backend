/* eslint-disable @typescript-eslint/no-unused-vars */
import { JwtService } from '@nestjs/jwt';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private JwtService: JwtService,
    private authService: AuthService, 
  ){}

  async canActivate( context: ExecutionContext ):Promise<boolean> {

    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Sin token autorizado');
    }

    try {
      const payload = await this.JwtService.verifyAsync<JwtPayload>(
        token,
        { secret: process.env.JWT_SEED }
      );
  
      

      const user = await this.authService.findUserById( payload.id);

      if(!user) throw new UnauthorizedException('Usuario inexistente...');
      if(!user.isActive) throw new UnauthorizedException('Usuario inactivo');
      
      request['user'] = user;

    } catch (error) {
      throw new UnauthorizedException();
    }


    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
    }
}
