Simple tool to interact with the Lulebo API.

## Usage
To create a user with the service use:
```
lulebo signup
```

After a user has been created, verify that you can log in with it.
```
lulebo url heater-start --username your_name
```

Finally, you can start the car heater with the following command.
```
lulebo heater start --username your_name
```

Alternately, you can generate a link, for e.g. bookmarking, that allows you to start the car heater without loggin in.
```
lulebo url heater-start --username your_name
```