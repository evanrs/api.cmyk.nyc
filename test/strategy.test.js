var Strategy = require('../src/strategy');

describe('Strategy', function () {
  let strategy = new Strategy(x => x);

  it('should be named cmyk', ( ) =>
    expect(strategy.name).to.equal('cmyk'))
});
