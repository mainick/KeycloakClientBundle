# Contributing

We welcome your contributions! If you wish to enhance this package or have found a bug,
feel free to create a pull request or report an issue in the [issue tracker](https://github.com/mainick/KeycloakClientBundle/issues).

We accept contributions via Pull Requests on [Github](https://github.com/mainick/KeycloakClientBundle).


## Pull Requests

- **[PSR-12: Extended Coding Style](https://www.php-fig.org/psr/psr-12/)** - The easiest way to apply the conventions is to install [PHP Coding Standards Fixer](https://cs.symfony.com/).

- **Add tests!** - Your patch won't be accepted if it doesn't have tests.

- **Document any change in behaviour** - Make sure the README and any other relevant documentation are kept up-to-date.

- **Consider our release cycle** - We try to follow SemVer. Randomly breaking public APIs is not an option.

- **Create topic branches** - Don't ask us to pull from your master branch.

- **One pull request per feature** - If you want to do more than one thing, send multiple pull requests.

- **Send coherent history** - Make sure each individual commit in your pull request is meaningful. If you had to make multiple intermediate commits while developing, please squash them before submitting.

- **Ensure tests pass!** - Please run the tests (see below) before submitting your pull request, and make sure they pass. We won't accept a patch until all tests pass.

- **Ensure no coding standards violations** - Please run PHP Coding Standards Fixer using the PSR-12 standard (see below) before submitting your pull request. A violation will cause the build to fail, so please make sure there are no violations. We can't accept a patch if the build fails.

## Running Tests

``` bash
composer test
```

## Running PHP Coding Standards Fixer dry-run

The rules usaged the PHP Coding Standards Fixer are defined in the `.php-cs-fixer.dist.php` file.

``` bash
composer lint
```

## Running PHP Coding Standards Fixer

``` bash
composer lint-fix
```

**Happy coding**!
