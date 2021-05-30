# Phone CRUD Backend [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the source code of the Flask App which exposes a REST Api with the ability to view/create/modify/delete entries of phones and phone brands. 

Built for `python3`, it connects to a database using the [MongoAlchemy](https://pythonhosted.org/Flask-MongoAlchemy/) package, which adds support for MongoDB on Flask. 

All the project information has been put together in the project [Wiki](https://github.com/balb0x/phone-crud-backend/wiki) 

### Deployment

The project has been configured to run in a docker container. To build the image, first execute this line on the cmd:

```
docker-compose build
```

Then, to run the container:

```
docker-compose up
```

The docker container builds the project and makes a MongoDB image so everything is integrated within the container.

### Build

Also, if you want to build the application yourself, you can install the python packages and run it:

```
python3 -m pip install -r requirements.txt
python3 app/main.py
```

### Usage

The backend exposes a simple API rest on port `5000`, to interact with the api you can use Postman and import the provided collection file: `phone-crud-backend.postman_collection`.
Refer to the project [Wiki/Endpoints](https://github.com/balb0x/phone-crud-backend/wiki/Endpoints) for a more detailed information of the api. 


### License

Phone CRUD Backend is [MIT licensed](./LICENSE)