import allowedOrigins from "./allowedOrigins";

const corsOptions = {
  origin: (origin: string | undefined, callback: Function) => {
    if (allowedOrigins.includes(origin as string) || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

export default corsOptions;
