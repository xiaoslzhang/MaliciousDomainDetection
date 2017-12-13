# coding:utf-8
# use python3

import json
import logging
import random
import requests


def virustotal_verify(key, domain, details=False):

    """
    Given a query, come back the result of the virustotal
    :param key: the key of virustotal query
    :param domain: the queried domain or url
    :param details: whether need to come back the details of result.
                    If True, result includes "positives"、"total"、all "scans"
                    If False, only return the scans of that "detected" is true
    :return:
            the query result, DICT type
            if null, the domain is clean;
            otherwise, the result is all conclusions of different verifications
    """

    api = 'https://www.virustotal.com/vtapi/v2/url/report'

    params = {'resource': domain, 'apikey': key}
    headers = {
        'Content-Type': 'Application/json',
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.72 Safari/537.36"
    }
    try:
        res = requests.get(api, params=params, headers=headers)

        if res.status_code == 200:
            data = json.loads(res.text)
            if details:
                return data
            else:
                s_data = data['scans']

                output = {}
                for k in s_data.keys():
                    v_data = s_data[k]
                    if v_data['detected']:
                        output[k] = v_data

                return output
        else:
            logging.error("the request comes back status: %s" % res.status_code)
    except Exception as e:
        logging.error("the request gets wrong with exception: %s" % e)


def per_query(domain):

    """
    just give a domain to get the virustotal result
    :param domain: the queried domain or url
    :return: the result of virustotal
    """

    keys = ['1b30b1d7d648ef7aa64be6191d7c6d769fe3c967bfcb2a22212633391db07a6d',
            '445d2a71594aa4fae68e3ba8a439fe1be81016618c18b3e57bf1a48231759936',
            'ae4fce44cc1a75d93e89c81d29c87d1633f0057fbc9b35f7eb2dc6cafc27cda1',
            'd8757693b393a6977b9ef5af6298901749a97d617a46dd5467e221365ab55697',
            'aeedc736e6878ffc82124c212cfd1e67a53ee2c30e1ef21898f97b6f8e771ea9',
            '4ab837a28fb4df2f3d9e8ccf6455fa62b9d72969a1458226a5f00a24efc66ed7',
            '9ae73e0e45c2e965de76088f980ad037b07f8e35b552cd64368b1aafeaed922b',
            'b0009bc813d71bc23036f25ab899d8f45d4e5376901d592d32d36d6caf4a2f50',
            'c5fa269ae76b812708dbae0739a3ead6b4db41b6631179513baa07ff97264d3f',
            '63c364ecb0fb8262d41ea60133af436f7e14f2d3bae6fe59161c9017a22b6ddf',
            '62658aecaa17105a30eec7667fd4f84208866a499d5a312d67a4b6ddc2d7ae8b',
            'b4e4576190dc24b7f6e84255bff769ea858f39fea4e9dd50a3aaacdfcec0c349',
            'd5136b27f6a82a6a77a69729e74b246232c23e445e69da471041e341c0ea02dc',
            'd8dc47742318db4c3f79b6b3a33ececc6b59a1906e6c64cdfe49406b3ae95e3f',
            'a5507d02d49ed9a6e70830cbe67282515ed42025b323c69dae660dd3395d4ce7',
            '4e17a7f503351e0f765c812a3ee2962ddce08f0c8fb8ccd9085262779bbeaed5',
            'd53ec9869c43db71a1d7d962bbe6801578e12f8aa0da2a744efa14619cd7c228',
            'b56a7837449f6bdd55eb3ec7e153d3a4c297c526be80ba9f04afe7e72e90c26d',
            'b9840ef367f50331b3323317acd5a1ad26af477871173212ec318bd6403bc50a',
            'ed2cc6f458d273b659f81049e2362c7190892614ddb9b207e9878c3d6afee46d',
            '37bb22f3f443eab8323c18cd13c5d3ed1014fb07436eb55e75dbeb6067149831',
            '4577d2711364f935b8422ce97f83de45155e59ce6bfd9fbe94870bf685e98305',
            'b7cd5ff9b5d3aefc758e0a5756b3a18186b475f7cd00be9eba4bf8c09692e914',
            'f3664a9faaf4f22b1cbfa057433b0028c2eb63fd2ef51643c861ff7a675e8bcb',
            '2286b37128ffc623ac86313af3d22e1ce7e3f536ed4c65e066c0a6ace53b4398',
            '6b4469f747b043d7abbb6bcab71d8d88d06fa649f99a85757a6603257fc67890',
            '54d7e7bf9c0fb1844f7ca5074f817789c45c4db3988c12dfe11cb69107b199c7',
            'ab8988ceb897116f2d8fd9c0282e9ae967abd7a0e3ee6e02bff58f4cf23d935b',
            'daa386b4ffeb8a9c48019e523b2d9df54ed562e77896e83ec4554051284f4437',
            'c517454624cd9df7f6e7cb8abb4ccbbbe3f131417bb52779b6d3522c9d59a0c9',
            '2d95fc457e2e43beeff1f985c56e4dfef0900acffc180377c17aae653da635e1',
            '1d834df9b992fbe49eeff586a5f2ff4ee2e1eb7557ad97c8b510402d9f550eeb',
            'f6a6d0cdc01b788a25d9852d51c89e64a422b1f5f1abc09ac265fbf1884fb572',
            '3933ff42cc560d8a4353987ba7dc7a38566ec14828c3b151d398c41b8dc2a66e',
            '0bbb694113ed4286bf29de4d2494f402cb839be9439166361aab3e9cdd87e996',
            '02fd5481b357699789c54f2ba09fb7c70357b07a5626fdfae19ec013cace5652',
            'b3440e2d3ae8a4ff2898b9a700617fbd9eb36aadd4777d4f9dfd290a72312a34',
            'a2c26e2400fa20e452417bc2afe6b04f2a11cd74e8b3dd7d397f07e48f772cc7',
            'f838f344b7c9618eeb121df91985d43e7da5abd0e301b62b5929fbf1bc1bc6fc',
            'a3bb939bca47ac920def2c634597c50f7bfaa1ad5b7636ddc2e55b61eef2ac34',
            '8d5cd7abc48a47607d64385db43f48754c21cb5f897ca4d6913cc0d1210f8ab9',
            '0bca7d0b9a349e7bd2bae95d703fdd9bf365a18708885e96f15f16e7a7d1ae39',
            'f7259036f4e4ff2d0f2b7d86eb69cfeb43529fb3aeadb16f125ac00055742aab',
            'bcbde2ac4c3ccb937d2295b4998a1d4df0ffdae9cf954b624993df2fce9a4488',
            '6e88b006fa17a7de60eda99c56dde8d59e4bff8f4285a6f9d9f6a4889f1c67a6',
            '4f37be5f3782a45b8545cf4abf5b6a91c81ef1f6d69ea1383f9a2dd68b83c530',
            'ff434f47699151d0559ab53ed4d07f6cf04f6c5b4fbfb6a9334b287844f1ae29',
            'f50f3fcd00bb7805f8d6b332c66359304837b445ebd64bfb8a349137e9d9a93d',
            '59817be843ae48190099889c3aca1c5b6fd12085b4efd7ed58f67307764eb6ee',
            'c2dca89846b51c05a7ae01a56cfd59ee578c7735237a39b072d4091b772d0a5b',
            'b2d9b8b3d1854c817ee6008f6954e20f4cb66314ac4d06148e82a4b61147e476',
            'c4f2ab829b77466e3503cc84f3a9ab88ad0f7d8be637e1a27056e9888ab6708b',
            '829a53d00bc15d243caf032b1fb22a14e75e9e98060681c960165d30c36b1d20',
            'fc8c85c89265c6ea255aab0a3bbbd2da59be8cdd0fa16cca53bf59772269ce13',
            'b7fc8c1aae50e71f970c16de8a4e20c4d262f3690a8c7abe059bf3e8bff8cea1',
            'ef06cf425fb17cbe0f1ce236e5d18de62450e90089314ddcf3893a433d16510d',
            '5fe063bacca66f549db1f4381b7f5f38234e499c1225066a006b0830f2eaaa59',
            '76714f33031a93498ed58cca5950a993c416cf38412e22e36ec17bf79c8f4669',
            '787c884bc7778f6befc49eaa72e62e5da9e4a85040e1e360c8dc2285f578796f',
            'db888aa7d8e2f7059e59b120153397e8c56046ea1d51d90288d66200e5558be7',
            '0db7731f919d1eb35ecbcd1c12d31f2cac35bc6ec601b72a47726122107a856b',
            'cf6a60dcb8a4f9bb125efdf917d45ceffe95b975b2eed469cd0b1fc77b15d093',
            'b767b730966bf3c57bbf0c5b5d5d7f7c437939e519b8a205f1dc1ec587810521',
            '5cbda9b78c01ff77f2daa55b4dc0fe8e8f9bd88b94aa278d73db94c3f464f5a2',
            '149d4eff8abfb477d6292ebfb60ee90b5faced043040c69db6c61b8e83c2813c',
            '2470e036180463be20d9b603f0eb22634a5eb617c565018c203e4e279a702c8b',
            '96aec67956f561b3748cb4fb836c9c88f4b5b5b6cfb0bf6a8ed73e5400e60899',
            '5bf8f6f39cb6e7db0b153a48d3970b84b09fca724d9fee57adaacef41cb63a76',
            '55c5d4a20c4c5ae6948851803273ac7502eda98cc2741a97adfa35eeb9eba34a',
            '0cd2a9d28aca076b3dce11e874b4cdfe3ca97093458df517121d45efac8191be',
            '4ae62b3e7c6bb078d92b65fb4e4237bd72e8d432dc413a5b5bd5f6d2a59e56bb',
            '9f463452412cfe808eda9ee0ac28b85e9e556601d9916172c23d23e5657da564',
            '24062f6ce8e2ce51719503e634a99cc22f13c53e188464c5321addc419213a22',
            'a3918bffabd94a396b59f132c1a2b95f376e34df0edf13c51e6bc604be82d5bb',
            'f5611882dd6f3c345910232d225ed5012c144645a31c6b199a03bf2eac2c8056',
            'c2ea2e5f66148d1379818a915197efca1ddb3a6734086f3e72ef7685b7e98889',
            '71cf89ef263903955f9c7b58897638cf081f0184367189d44531fddca2c0bfa0',
            '52831ff4e482982118d8039b51964d8c6a4e3c583c5ad03518fb2e82b5864653',
            '5f07a63179f229a50716c97e875a7b6298bd5a89d25e663fe7e391ceeb57a117',
            '36fd21588bac96f60698705c1df1464ed496c8f2bc812153c467e48d5a2eade1'
            ]
    num = random.randint(0, 79)
    return virustotal_verify(keys[num], domain, False)

#if __name__ == "__main__":
    # 注意查询速度  1key 4query 1minute
#    print(per_query("www.baidu.com"))
#    print(per_query("abhedya.net"))
#    print(per_query("hitnrun.com.my"))
#    print(per_query("mail.spa.gov.sa"))
#    print(per_query("baidu.com"))
