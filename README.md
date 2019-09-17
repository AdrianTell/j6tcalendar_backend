# CoOp_Calendar_Backend

To run backend locally:

1. clone the repo into a directory

2. cd into the 'calendar_project'

3. build pipenv environment by running
```
pipenv update
```
4. initialize pipenv environment by running
```
pipenv shell
```
5. make initial migrations by running
```
python manage.py migrate
```
6. run server locally, the server will be running on whatever the private ip address is, port 8000
```
python manage.py runserver
```
