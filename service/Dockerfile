FROM node:20

WORKDIR /service

COPY package*.json ./

RUN npm install

COPY . .

CMD ["node", "index.js"]