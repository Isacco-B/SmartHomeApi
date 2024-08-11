import { HttpException } from "../exceptions";

export const errorHandler = (statusCode: number, message: string) => {
  const error = new HttpException(statusCode, message);
  return error;
};
