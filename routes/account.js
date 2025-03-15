const express = require('express');
const router = express.Router();
const pools = require('../db');
const config = require('../config');

router.get('/account', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const username = req.session.user;
  const realms = [];
  const showModal = req.query.registered === 'true';

  try {
    // Fetch account details
    const [account] = await pools.auth.query(
      'SELECT id, online, mutetime, mutereason FROM account WHERE username = ?',
      [username]
    );
    if (!account.length) throw new Error('Account not found');
    const accountId = account[0].id;
    const isOnline = account[0].online === 1;
    const muteTime = account[0].mutetime;
    const muteReason = account[0].mutereason || null;

    // Check ban status
    const [ban] = await pools.auth.query(
      'SELECT banreason, active FROM account_banned WHERE id = ? AND active = 1',
      [accountId]
    );
    const banStatus = ban.length > 0 ? ban[0].banreason : null;
    const isActive = ban.length === 0 || ban[0].active === 0;

    // Iterate through realms
    for (const realm of config.db.realms) {
      const realmData = { name: realm.display_name || 'Characters', characters: [] };

      try {
        const [chars] = await pools[realm.db_name].query(
          `SELECT guid, name, race, class, level, money, online 
           FROM characters WHERE account = ?`,
          [accountId]
        );
        console.log(`Characters for ${realm.db_name}:`, chars);

        for (const char of chars) {
          const money = char.money || 0;
          const gold = Math.floor(money / 10000);
          const silver = Math.floor((money % 10000) / 100);
          const copper = money % 100;

          const [equippedItems] = await pools[realm.db_name].query(
            `SELECT ci.item, ii.entry, ii.name, ii.quality, ii.icon 
             FROM character_inventory ci 
             JOIN item_instance ii ON ci.item = ii.guid 
             WHERE ci.guid = ? AND ci.slot BETWEEN 0 AND 18 AND ci.bag = 0`,
            [char.guid]
          );
          console.log(`Equipped items for ${char.name}:`, equippedItems);

          const [inventoryItems] = await pools[realm.db_name].query(
            `SELECT ci.item, ii.entry, ii.name, ii.quality, ii.icon 
             FROM character_inventory ci 
             JOIN item_instance ii ON ci.item = ii.guid 
             WHERE ci.guid = ? AND ci.bag != 0`,
            [char.guid]
          );
          console.log(`Inventory items for ${char.name}:`, inventoryItems);

          realmData.characters.push({
            name: char.name || 'Unnamed',
            level: char.level || 0,
            race: getRaceName(char.race),
            class: getClassName(char.class),
            online: char.online === 1,
            money: { gold, silver, copper },
            items: (equippedItems || []).map(item => ({
              id: item.entry,
              name: item.name || 'Unknown Item',
              quality: getQualityName(item.quality),
              icon: item.icon || 'inv_misc_questionmark'
            })),
            inventory: (inventoryItems || []).map(item => ({
              id: item.entry,
              name: item.name || 'Unknown Item',
              quality: getQualityName(item.quality),
              icon: item.icon || 'inv_misc_questionmark'
            }))
          });
        }
        realms.push(realmData);
      } catch (charErr) {
        console.log(`No characters or error for ${realm.db_name}: ${charErr.message}`);
        realms.push(realmData); // Still add the realm even if empty
      }
    }

    res.render('account', {
      user: username,
      realms,
      banStatus,
      isOnline,
      isActive,
      muteTime: muteTime > 0 ? new Date(muteTime * 1000).toLocaleString() : null,
      muteReason,
      showModal,
      errorMessage: null
    });
  } catch (err) {
    console.error('Account fetch error:', err);
    res.render('account', {
      user: username,
      realms: [],
      banStatus: null,
      isOnline: false,
      isActive: true,
      muteTime: null,
      muteReason: null,
      showModal: false,
      errorMessage: err.message
    });
  }
});

function getRaceName(raceId) {
  const races = {
    1: 'Human', 2: 'Orc', 3: 'Dwarf', 4: 'Night Elf', 5: 'Undead',
    6: 'Tauren', 7: 'Gnome', 8: 'Troll', 10: 'Blood Elf', 11: 'Draenei'
  };
  return races[raceId] || 'Unknown';
}

function getClassName(classId) {
  const classes = {
    1: 'Warrior', 2: 'Paladin', 3: 'Hunter', 4: 'Rogue', 5: 'Priest',
    6: 'Death Knight', 7: 'Shaman', 8: 'Mage', 9: 'Warlock', 11: 'Druid'
  };
  return classes[classId] || 'Unknown';
}

function getQualityName(qualityId) {
  const qualities = { 0: 'Poor', 1: 'Common', 2: 'Uncommon', 3: 'Rare', 4: 'Epic', 5: 'Legendary' };
  return qualities[qualityId] || 'Common';
}

module.exports = router;