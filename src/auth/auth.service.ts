import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = new this.userModel({
        ...userData,
        password: hashedPassword,
      });
      await newUser.save();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(
          ` ${createUserDto.email} Email already exists`,
        );
      }
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials - email');
    }

    if (!bcrypt.compare(password, user.password)) {
      throw new UnauthorizedException('Invalid credentials - password');
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: 'token',
    };
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    console.log(updateAuthDto);
    return `This action updates a #${id} auth `;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
