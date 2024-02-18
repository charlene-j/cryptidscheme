use rand_core::{CryptoRng, RngCore};
use rand::Rng;
use curve25519_dalek::{ristretto::RistrettoPoint,scalar::Scalar,traits::Identity,constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;
use std::{time::Duration,time::Instant,io,io::Write,fs::File,fs};

//https://docs.rs/curve25519-dalek/latest/curve25519_dalek/

// Definition of structure for proofs
#[derive(Debug)]
pub enum Proof{

    ProofMaybe{r_0: Vec<RistrettoPoint>, r_1: Vec<RistrettoPoint>, c_1: Vec<Scalar>, z_1: Vec<Scalar>},
    ProofNo{y_0_p: RistrettoPoint, y_1_p: Vec<RistrettoPoint>, r_0: RistrettoPoint, r_r: Vec<RistrettoPoint>, s_0: RistrettoPoint, s_s: Vec<RistrettoPoint>, u_u: Scalar, v_v: Scalar},
    Error{err: bool},
}

pub struct Proofgame0{r_0: Vec<RistrettoPoint>, r_1: Vec<RistrettoPoint>, r_2: Vec<RistrettoPoint>, c_c: Vec<Scalar>, z_z: Vec<Scalar>}
    
pub struct Proofgame1{r_01: Vec<RistrettoPoint>,r_1: Vec<RistrettoPoint>,r_02: Vec<RistrettoPoint>,r_2: Vec<RistrettoPoint>, c_1: Vec<Scalar>, c_2: Vec<Scalar>, z_1: Vec<Scalar>, z_2: Vec<Scalar>}

pub struct Proofgame2{r_0: Vec<RistrettoPoint>, r_a: Vec<RistrettoPoint>, r_1: Vec<RistrettoPoint>, r_2: Vec<RistrettoPoint>, c_c: Vec<Scalar>, z_1: Vec<Scalar>, z_2: Vec<Scalar>}

pub struct Proofgame3{y_0_p: RistrettoPoint,y_1_p: RistrettoPoint,y_2_p: RistrettoPoint,r_00: RistrettoPoint, s_00: RistrettoPoint, r_1: RistrettoPoint, s_1: RistrettoPoint, r_2: RistrettoPoint, s_2: RistrettoPoint, r_03: Vec<RistrettoPoint>,r_3: Vec<RistrettoPoint>, r_04: Vec<RistrettoPoint>, r_4: Vec<RistrettoPoint>,r_056: RistrettoPoint, r_5: RistrettoPoint, r_6: RistrettoPoint, r_07: Vec<RistrettoPoint>, r_7: Vec<RistrettoPoint>,c_00: Scalar, c_01: Scalar, c_3: Vec<Scalar>, c_4: Vec<Scalar>, c_7:Vec<Scalar>, u_u: Scalar, v_v: Scalar, z_3: Vec<Scalar>, z_4: Vec<Scalar>,z_056: Scalar, z_7: Vec<Scalar>}

// Generates a random scalar from curve25519_dalek librairy
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// Generates a random RistrettoPoint
fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// Converts a [u8;32] in Scalar
fn convert_scalar(a: [u8;32]) -> Scalar{
    
    let s = Scalar::from_bytes_mod_order(a);
    return s
}	       

// Converts a RistrettoPoint in [u8;32]
fn convert_ris (t: RistrettoPoint) -> [u8;32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption / Decryption
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint) -> (RistrettoPoint,RistrettoPoint,Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
pub fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint,pk: RistrettoPoint,m: RistrettoPoint)-> (RistrettoPoint,RistrettoPoint){ 
	
    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1,c2)
}
	
fn dec_elgamal(sk: Scalar,c1: RistrettoPoint,c2: RistrettoPoint)-> RistrettoPoint{ 

    let m = c2 - sk * c1 ;
    return m
}
	
// Hash on Vec<RistrettoPoint> 
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8;32]> = Vec::new();
		
    for p in input {
	let p_p = convert_ris(p);
	k.push(p_p);
    }

    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8;32]>::from_hex(h);
    let mut u = [0u8;32];
        
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }   
    return convert_scalar(u);      
}
 
// Initializes vector  
fn init_vec_ris(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity();t];
    return vec
}

fn init_vec_scal(t: usize) -> Vec<Scalar> {
    
    let vec = vec![convert_scalar([0u8;32]);t];
    return vec
}
    	   
// Setup of map, clues...

// Generation of types and properties
pub fn typesandproperties<T: CryptoRng + RngCore>(csprng: &mut T) -> (Vec<RistrettoPoint>,Vec<RistrettoPoint>){
    
    let mut t: Vec<RistrettoPoint> = Vec::new();
    let mut p: Vec<RistrettoPoint> = Vec::new();
	
    // gen types
    let mut k = 0;
    while k < 5{
        let ti = random_point(csprng);
        t.push(ti);
        k = k + 1;
    }
    
    // gen properties
    k = 0;
    while k < 14{
        let pi = random_point(csprng);
        p.push(pi);
        k = k + 1;
    }
    return(t,p)
}


// Generates a specific cell with type t and properties p
pub fn gencell (t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, w: usize, mut x: Vec<usize>) -> (RistrettoPoint, Vec<RistrettoPoint>){
    
    let id = RistrettoPoint::identity();
    let ti = t[w];
    let mut pi: Vec<RistrettoPoint> = Vec::new();
    x.sort();

    let mut k = 0;
    for i in 0..14{
    	if k < x.len(){
    	    if i == x[k]{
        	let px = p[i];
        	pi.push(px);
        	k = k + 1;
            }
            else {
            	pi.push(id);
            }
        }
        else{
            pi.push(id);
        }
    }
    return(ti,pi)
}

// Generates a random cell
pub fn randomcell (t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>) -> (RistrettoPoint, Vec<RistrettoPoint>){
     
    let mut rng = rand::thread_rng(); 
    
    let w: usize = rng.gen_range(0..5);
    
    let n: usize = rng.gen_range(1..13); // n = number of properties
    let mut x:  Vec<usize> = Vec::new(); 
    
    let mut k = 0;
    while k < n{
       
        let z : usize = rng.gen_range(0..14);
        if x.contains(&z){
            continue;
        }
        else {
            x.push(z);
        }
        k = k + 1;    
    }
    let ci = gencell(t,p,w,x);
    return ci
}

/// Build a  random clue: i = 0 correspond to (tj,tk,bot) with tj =/= tk, i = 1 corespond to (bot,bot,p) with p in pj, i = 2 correspond to (ti,tk,bot) with tj =/= tk =/= ti =/= tj, i = 3 correspond to (bot,bot,p) with p not in pj
pub fn buildrandomclue(t: Vec<RistrettoPoint>,p: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,k: usize) -> Vec<RistrettoPoint>{

    let mut rng = rand::thread_rng(); 
    let bottom = RISTRETTO_BASEPOINT_POINT; 
    
    if k == 0{

        let mut r1 = rng.gen_range(0..5);
        while t[r1] == tj{
    	    r1 = rng.gen_range(0..5);    
        }
        let r = rng.gen_bool(0.5);
        if r == true{
            return vec![tj,t[r1],bottom];
        }
        else{
            return vec![t[r1],tj,bottom];
        }
    }
    if k == 1{
    
        let mut r2 = rng.gen_range(0..pj.len());
        while pj[r2] == RistrettoPoint::identity(){
            r2 = rng.gen_range(0..pj.len());
        }
        return vec![bottom,bottom,pj[r2]];
    }    
    else{
    	println!("Please give a correct form of clue");
    	return vec![bottom,bottom,bottom];
    }	
}


pub fn buildcluesplayers(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, tj : RistrettoPoint, pj: Vec<RistrettoPoint>, cluesforms: Vec<usize>) -> Vec<Vec<RistrettoPoint>>{
    
    let mut cluesplayers: Vec<Vec<RistrettoPoint>> = Vec::new();
    for i in cluesforms{
        let clue = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),i);
    	cluesplayers.push(clue);
    }
    return cluesplayers 	
}
    
pub fn buildclueskeys<T: CryptoRng + RngCore>(csprng: &mut T, genplayers: Vec<RistrettoPoint>, cluesplayers: Vec<Vec<RistrettoPoint>>) -> (Vec<Vec<RistrettoPoint>>, Vec<Scalar>){
   
    let mut pcplayers: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut scplayers: Vec<Scalar> = Vec::new();	
    for i in 0..genplayers.len(){
    	let keyc = genclue(csprng, genplayers[i], (&cluesplayers[i]).to_vec());
    	pcplayers.push(keyc.0);
    	scplayers.push(keyc.1); 
    }
    return (pcplayers,scplayers)	
}
    	
pub fn buildmaster< T: CryptoRng + RngCore >(csprng: &mut T, g: RistrettoPoint, tj: RistrettoPoint, pj: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){
	
    let key = gen_elgamal(csprng,g); // key.0 = g0, key.1 = pk, key.2 = sk
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    let e0 = enc_elgamal(csprng,g,pc[0],tj);
    pc.push(e0.0); //c1
    pc.push(e0.1); //c2
    for c in pj{
	let e = enc_elgamal(csprng,g,pc[0],c);
	pc.push(e.0); //c1
	pc.push(e.1); //c2	
    }
    return (pc, key.2)
}

pub fn buildrandommap (t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, n: usize) -> (Vec<RistrettoPoint>,Vec<Vec<RistrettoPoint>>){

    let mut maptypes: Vec<RistrettoPoint> = Vec::new();
    let mut mapprop: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut k = 0;
    while k < n{
        let cj = randomcell((&t).to_vec(), (&p).to_vec());
        let tj = cj.0;
        let pj = cj.1;
        maptypes.push(tj);
        mapprop.push(pj);
        k = k + 1; 
    }
    return(maptypes,mapprop);
}

// Measures the running time of algorithm genclue, openclue, play, verify and the size of pc and proof for the protocol cc2
pub fn mesuretimeandsize<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, iter: u32){
    
    let mut sumgenclue = vec![Duration::ZERO;4];
    let mut sumopenclue = vec![Duration::ZERO;4];
    let mut sumplay = vec![Duration::ZERO;4];
    let mut sumverify = vec![Duration::ZERO;4];
    
    let mut meangen = vec![Duration::ZERO;4];
    let mut meanopen = vec![Duration::ZERO;4];
    let mut meanplay = vec![Duration::ZERO;4];
    let mut meanverify = vec![Duration::ZERO;4];
    
    let mut pcsize = vec![0,0,0,0];
    let mut proofsize = vec![0,0,0,0];
    
    let mut meanpcsize = vec![0,0,0,0];
    let mut meanproofsize = vec![0,0,0,0];
  
    for _j in 0..iter{
    	
    	// Defines a random map
    	let maps = typesandproperties(csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    	let t = maps.0; // vector of 5 elements
    	let p = maps.1; // vector of 14 elements
    	
        // Defines a random cell
        let cj = randomcell((&t).to_vec(),(&p).to_vec());
        let tj = cj.0;
        let pj = cj.1;
        
    	// Defines four different form of random clues 
        let clue0 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),0);
        let clue1 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),1);
        let clue2 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),2);
        let clue3 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),3);
       
        let cluesplayers = vec![(&clue0).to_vec(),(&clue1).to_vec(),(&clue2).to_vec(),(&clue3).to_vec()];     
    
    	let answerplayer = vec![0,1];  
    
    	for i in 0..4{
    
    	    let startgen = Instant::now();
            let keyc = genclue(csprng, g0, (&cluesplayers[i]).to_vec()); 
	    let gentime = startgen.elapsed();
	    sumgenclue[i] += gentime; 
	    
	    let pc = keyc.0; 
    	    let sc = keyc.1;
    	    let _ = writepc((&pc).to_vec());
    	    let pcdata = fs::metadata("pc.txt");
    	    pcsize[i] += pcdata.expect("REASON").len();
    	    
    	    let startopenclue = Instant::now();
    	    let open = openclue((&pc).to_vec(),sc);
    	    let opencluetime = startopenclue.elapsed();
    	    assert!(open == (&cluesplayers[i]).to_vec(),"open != clue");
    	    //println!("open = clue: {:?}", open == (&cluesplayers[i]).to_vec());
    	    sumopenclue[i] += opencluetime;
    	    
    	    let mut answer: usize = 2;
    	    if i == 0 || i == 1{
    	    	answer = answerplayer[1];
    	    }
    	    if i == 2 || i == 3{
    	    	answer = answerplayer[0];
    	    }
    	    
    	    /*let mut badanswer: usize;
    	    if answer == 0{
        	badanswer = 1;
   	    }
    	    else{
    	        badanswer = 0;	
   	    }*/
    	
            let startplay = Instant::now();
            let proof = play(csprng,g0,(&pc).to_vec(),sc,tj,(&pj).to_vec(),answer);
            let playtime = startplay.elapsed();
            sumplay[i] += playtime;
            let _ = writeproof(&proof);
    	    let proofdata = fs::metadata("proof.txt");
    	    proofsize[i] += proofdata.expect("REASON").len();
        
            let startverify = Instant::now();
            let b = verify(g0,proof,(&pc).to_vec(),tj,(&pj).to_vec(),answer);
            assert!(b == true, "verify == false");
            //println!("verify : {:?}", b == true);
            let verifytime = startverify.elapsed(); 
            sumverify[i] += verifytime;  
        }        
    }  
    for i in 0..4{
    
    	meangen[i] = sumgenclue[i]/iter;
    	meanopen[i] = sumopenclue[i]/iter;
    	meanplay[i] = sumplay[i]/iter;
    	meanverify[i] = sumverify[i]/iter;
    	
    	meanpcsize[i] = pcsize[i]/u64::from(iter);
    	meanproofsize[i] = proofsize[i]/u64::from(iter);
    
    	println!("clue {:?} : mean of running time over {:?} iter for genclue {:?}, for openclue {:?}, for play {:?}, for verify {:?}",i+1,iter,meangen[i],meanopen[i],meanplay[i],meanverify[i]);
    	println!("clue {:?} : mean of size file over {:?} iter for pc {:?} bytes, for proof {:?} bytes",i+1,iter,meanpcsize[i],meanproofsize[i]);    
    } 
} 
  
// For measuring memory
pub fn writepc(pc: Vec<RistrettoPoint>) -> io::Result<()> {
    let mut file = File::create("pc.txt")?;
    file.write_fmt(format_args!("{:?}", pc))?;
    return Ok(())
}

pub fn writeproof(proof: &Proof) -> io::Result<()> {
    let mut file = File::create("proof.txt")?;
    file.write_fmt(format_args!("{:?}", proof))?;
    return Ok(())
}
  
// Scheme cc2
//csprng: random generator, g0: generator used to generates the key pk of the player, clue: vector of 3 RistrettoPoint which represent the clue = (C1,C2,C3), tj: type of the cell committed, pj: properties of the cell committed, answerplayer correspond to  bottom: correspond to a RistrettoPoint

pub fn schemecc2<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,clue: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize){
              
    let startgenclue = Instant::now();
    let keyc = genclue(csprng,g0,(&clue).to_vec()); 
    let gentime = startgenclue.elapsed();
    println!("genclue took {:?}", gentime);
                       
    let pc = keyc.0; //pc = (pk, E1=(c11,c21), E2=(c12,c22), E3=(c13,c23) , Ei=Enc_pk(clue[i])
    let _ = writepc((&pc).to_vec());
    let sc = keyc.1; //sc = sk

    let startopenclue = Instant::now();
    let open = openclue((&pc).to_vec(),sc);
    let opentime = startopenclue.elapsed();
    println!("openclue took {:?}", opentime);    
    assert!(open == clue, "open != clue");
    //println!("open == clue: {:?}", open == clue);
	
    let startplay = Instant::now();
    let proof = play(csprng,g0,(&pc).to_vec(),sc,tj,(&pj).to_vec(),answer);
    let _ = writeproof(&proof);
    let playtime = startplay.elapsed();
    println!("play took {:?}",playtime);
	    
    let startverify = Instant::now();
    let b = verify(g0,proof,(&pc).to_vec(),tj,(&pj).to_vec(),answer);
    let vertime = startverify.elapsed(); 
    println!("verify took {:?}\n",vertime);
    assert!(b == true,"verify == false");
    //println!("verify : {:?}", b == true);

    println!("answer: {:?}; verify: {:?}\n",answer,b); 	
}

// Functions for the protocol vcc

// Genclue: g0 is the generator used to generate the player public key
pub fn genclue <T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>,Scalar){

    let key = gen_elgamal(csprng,g0); // key.0 = g, key.1 = pk, key.2 = sk
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue{
        let e = enc_elgamal(csprng,g0,pc[0],c);
	pc.push(e.0); //c1
	pc.push(e.1); //c2	
    }
    return (pc, key.2)
}  

// Openclue
pub fn openclue(pc: Vec<RistrettoPoint>,sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc,pc[k],pc[k+1]);
        clue.push(c); 
        k +=2;  
    } 
    return clue
}

// Answer
pub fn funanswer(clue: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>) -> usize{
    
    let bottom = RISTRETTO_BASEPOINT_POINT;
    if (clue[0] == tj || clue[1] == tj) && clue[2] == bottom{
        return 1
    }
    if clue[0] == bottom && clue[1] == bottom{
        for prop in pj{
            if clue[2] == prop{
                return 1
            }       
        }
    }
    return 0
}

// y0 is the public key pk of the player, y is the vector of "c2/tj" or "c2/p" s.t. Dec_sk((c1,c2)) = tj or p in pj, g0 is the generator used to generates the public key of the player, g is the vector of "c1" s.t. Dec_sk((c1,c2)) = tj or p in pj. x is the secret key sk of the player. (we prove also that the player use his correct secret key associated to the public key)

// prove play maybe 
fn prove_play_maybe<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values");
    	return  Proof::Error{err: false};
    }
    // Find the index w of the type or property of the cell committed s.t. c2/tj or c2/p equal to c1^sk
    let mut k = 0;
    while k < y.len() && y[k] != x * g[k]{
        k += 1;
    }
    let mut w = k;
    if w == y.len(){
        w -= 1;
    }    
    
    let mut r = init_vec_ris(y.len()); // vector of commit r
    let mut r0 = init_vec_ris(y.len());
    
    let rr = random_scalar(csprng); // picks a random scalar
    
    r0[w] = rr * g0;
    r[w] = rr * g[w];

    // simulation of proof for the yi such that yi =/= gi^x
    let mut c = init_vec_scal(y.len());  // ci is the challenge correspond to (yi,gi)
    let mut z = init_vec_scal(y.len());	 // zi is the respond correspond to (yi,gi)
    
    let respsim = simul_maybe(csprng,y0,(&y).to_vec(),g0,(&g).to_vec(),(&r0).to_vec(),(&r).to_vec(),(&c).to_vec(),(&z).to_vec(), w);
    
    r0 = respsim.0;
    r = respsim.1; 
    c = respsim.2; 
    z = respsim.3;

    // build the challenge:  
    let mut conc: Vec<RistrettoPoint> = Vec::new();   //build the vector for concatenation and hash    
    conc.extend((&r0).to_vec());
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc); // cc is the general challenge = sum of all ci
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum = sum + chall;
    }
    c[w] = cc - sum; 
    
    // response:
    z[w] = rr + c[w] * x;

    return Proof::ProofMaybe{r_0: r0, r_1: r, c_1: c, z_1: z};
}

// simulator for the yi such that yi =/= gi^x 
fn simul_maybe<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,mut r0: Vec<RistrettoPoint>,mut r: Vec<RistrettoPoint>,mut c: Vec<Scalar>,mut z: Vec<Scalar>,w: usize) -> (Vec<RistrettoPoint>,Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){
    
    for k in 0..y.len(){
        if k != w {
            let chall = random_scalar(csprng);
            c[k] = chall;
            let zz = random_scalar(csprng);
            z[k] = zz;
            r[k] = zz * g[k] - chall * y[k]; 
            r0[k] = zz * g0 - chall * y0;  
        }
    }
    return(r0,r,c,z)
}

fn verify_play_maybe(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, r0: Vec<RistrettoPoint>, r: Vec<RistrettoPoint>, c: Vec<Scalar>, z: Vec<Scalar>) -> bool{
	
    // computes the hash from the given values
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.extend((&r0).to_vec());
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc);
    let mut sum = convert_scalar([0u8;32]);
   
    for chall in &c{
        sum += chall;
    }
    
    // verify the computed hash is the sum of challenge and zi *gi = ri + cc * yi
    if cc == sum {
    	for i in 0..y.len(){
    	    if z[i] * g[i] != r[i] + c[i] * y[i] || z[i] * g0 != r0[i] + c[i] * y0{
        	return false   
            }
        }
        return true;
    }
    else{
        return false      
    }    
}
	
fn prove_play_no<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values");
    	return  Proof::Error{err: false};
    }

    let bb = random_scalar(csprng);
    let aa = x*bb;
	
    // commit 
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);
         
    let mut r: Vec<RistrettoPoint> = Vec::new(); 
    let r0 = rr * g0;
    for gg in &g{
        r.push(rr*gg);
    }
    
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-*yy);
    }
    
    let mut s: Vec<RistrettoPoint> = Vec::new(); 
    let s0 = ss*h0;
    for hh in &h{
        s.push(ss*hh);
    }
    
    let y0_p = aa * g0 + bb * h0;	// =1
    let mut y_p: Vec<RistrettoPoint> = Vec::new(); 

    for k in 0..g.len(){
	y_p.push(aa * g[k] + bb * h[k]);
    }
    
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);   
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    let cc = hash_vec(conc);
    
    let uu = rr + cc * aa;
    let vv = ss + cc * bb;
    
    return Proof::ProofNo{y_0_p: y0_p, y_1_p: y_p, r_0: r0, r_r: r, s_0: s0, s_s: s, u_u: uu, v_v: vv}; 	   
}   
  
fn verify_play_no(y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,h0: RistrettoPoint,h: Vec<RistrettoPoint>,y0_p: RistrettoPoint,y_p: Vec<RistrettoPoint>,r0: RistrettoPoint,r: Vec<RistrettoPoint>,s0: RistrettoPoint,s: Vec<RistrettoPoint>,uu: Scalar,vv: Scalar) -> bool{

    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    
    let cc = hash_vec(conc);
    
    if y0_p == RistrettoPoint::identity() && uu*g0 + vv*h0 == r0 + s0 + cc*y0_p{
    	for k in 0..y_p.len(){
            if y_p[k] == RistrettoPoint::identity(){ // we want y_p != id
                return false;
            }
            else{
                if uu*g[k] + vv*h[k] != r[k] + s[k] + cc*y_p[k]{
                    return false;
                }
            }
        }
    }
    else{
    	return false
    } 
    return true       
}

// g0 is the generator used to build the public key of player, pc is the public clue of the player, sc is the private clue of the player, (tj,pj) is the cell committed, answer is the response give by the payer for the cell (tj,pj)
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,pc: Vec<RistrettoPoint>,sc: Scalar,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize)-> Proof{

    let y0 = pc[0];

    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
     
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
	
    if answer == 1{ // maybe
        return prove_play_maybe(csprng, y0, y, g0, g, sc);  
    }
    if answer == 0{ // no
    	return prove_play_no(csprng, y0, y, g0, g, sc);
    }
    else{
	println!("Please give a correct answer");
	return Proof::Error{err: false};
    }	
}

pub fn verify(g0: RistrettoPoint,proof: Proof,pc: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize) -> bool{	
    
    let mut b = false;
    
    let y0 = pc[0];

    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
     
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
    
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-*yy);
    }
		
    match proof{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_1} => { 
    	    if answer == 1{
    		b = verify_play_maybe(y0, y, g0, g, r_0, r_1, c_1, z_1); 
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} =>{ 
    	    if answer == 0{
    		b = verify_play_no(y0, y, g0, g, h0, h, y_0_p, y_1_p, r_0, r_r, s_0 ,s_s, u_u, v_v);
    	    }
    	},
    	Proof::Error{err} => {   	
   	    if answer != 0 || answer != 1{
   		println!("Please give a correct answer");
   		b = err;
   	    }
    	},
    }
    return b  
}

// provegame and verifygame

pub fn provegame<T: CryptoRng + RngCore>(csprng: &mut T,t: Vec<RistrettoPoint>,p: Vec<RistrettoPoint>,maptypes: Vec<RistrettoPoint>,mapprop: Vec<Vec<RistrettoPoint>>,j: usize, genmaster: RistrettoPoint,genplayers: Vec<RistrettoPoint>,pcplayers: Vec<Vec<RistrettoPoint>>,scplayers: Vec<Scalar>) -> (Vec<RistrettoPoint>,Proofgame0,Proofgame1, Vec<Proofgame2>, Vec<Proofgame3>){
    
    let bottom = RISTRETTO_BASEPOINT_POINT;
    
    let n = maptypes.len(); // number of cells
    let keyc = buildmaster(csprng,genmaster,maptypes[j],(&mapprop[j]).to_vec());
    let pg = keyc.0;
    let sc = keyc.1;
     
    // Proof 0
    
    //sum el
    let mut sumc1 = RistrettoPoint::identity(); // c1 associated with tj pj
    let mut sumc2 = RistrettoPoint::identity(); // c2	
    let mut k = 3; // pg[0] = pk , pg[1] = c10, pg[2] = c20
    while k < 2*(p.len())+3{
        sumc1 += pg[k]; 
        sumc2 += pg[k+1]; 
        k += 2;
    }
    //sum pi for all cell_i
    let mut sumi: Vec<RistrettoPoint> = Vec::new();
    for i in 0..n{
       let mut sum = RistrettoPoint::identity();
       for l in 0..14{
	   sum += mapprop[i][l]; // hi = p1i +... p14i
       }
       sumi.push(sum); // sum(cell_i)
    }
    
    let ghl = vec![sumc1;n];
    let mut yhl = init_vec_ris(n);
    for i in 0..n{
        yhl[i] = sumc2 - sumi[i];
    }
    
    let ge0 = vec![pg[1];n];
    let mut ye0 = init_vec_ris(n);
    for i in 0..n{
    	ye0[i] = pg[2] - maptypes[i];
    }
    
    let proof0 = provegame0(csprng, pg[0], yhl, ye0, genmaster, ghl, ge0, sc);
    
    // Proof 1
    
    let mut c1l: Vec<RistrettoPoint> = Vec::new();
    let mut c2pl: Vec<RistrettoPoint> = Vec::new();
    let mut c2l: Vec<RistrettoPoint> = Vec::new();
    k = 3;
    while k < 2*(p.len())+3{
        c1l.push(pg[k]); 
        c2pl.push(pg[k+1]);
        c2l.push(pg[k+1]);
        k += 2;
    }
    for i in 0..p.len(){
        c2pl[i] = c2pl[i] - p[i];
    }
    
    let proof1 = provegame1(csprng, pg[0], c2pl, c2l, genmaster, (&c1l).to_vec(), (&c1l).to_vec(), sc);
    
    
    let mut proof2: Vec<Proofgame2> = Vec::new();
    let mut proof3: Vec<Proofgame3> = Vec::new();

    for player in 0..genplayers.len(){
    
    // Proof 2	
    
    let mut y: Vec<RistrettoPoint> = Vec::new();
    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut h: Vec<RistrettoPoint> = Vec::new();
    	
    y.push(pg[2]-pcplayers[player][2]);
    y.push(pg[2]-pcplayers[player][4]);
    	
    g.push(pg[1]);
    g.push(pg[1]);
    	
    h.push(-pcplayers[player][1]);
    h.push(-pcplayers[player][3]);
    		
    let mut l = 3;
    while l < pg.len(){
    	y.push(pg[l+1]-pcplayers[player][6]);
    	h.push(-pcplayers[player][5]);
   	g.push(pg[l]); 	    
    	l += 2;
    }
    
    let proof2player = provegame2(csprng,pg[0],pcplayers[player][0], y, genmaster, genplayers[player], g, h, sc, scplayers[player]);
        proof2.push(proof2player);  
        
    // Proof 3
          
    let y1 = pcplayers[player][6] - bottom;
    let g1 = pcplayers[player][5];
    let y2 = pcplayers[player][2] - pcplayers[player][4];  // same as y5
    let g2 = pcplayers[player][1] - pcplayers[player][3]; // same as g5
      	
    let mut y3: Vec<RistrettoPoint> = Vec::new();
    let mut g3: Vec<RistrettoPoint> = Vec::new();
    let mut y4: Vec<RistrettoPoint> = Vec::new();
    let mut g4: Vec<RistrettoPoint> = Vec::new();       
        
    for i in 0..t.len(){
        y3.push(pcplayers[player][2]-t[i]);
        y4.push(pcplayers[player][4]-t[i]); 
        g3.push(pcplayers[player][1]);
        g4.push(pcplayers[player][3]);
    }
        
    let y6 = pcplayers[player][4] - bottom;
    let g6 = pcplayers[player][3];
        
    let mut y7: Vec<RistrettoPoint> = Vec::new();
    let mut g7: Vec<RistrettoPoint> = Vec::new();
        
    for k in 0..p.len(){
        y7.push(pcplayers[player][6]-p[k]);
        g7.push(pcplayers[player][5]);
    }
        
    let proof3player = provegame3(csprng,pcplayers[player][0],y1,y2,y3,y4,y2,y6,y7,genplayers[player],g1,g2,g3,g4,g2,g6,g7,scplayers[player]);
    proof3.push(proof3player);
         
    }
    return (pg,proof0,proof1,proof2,proof3);
}  

pub fn verifygame(t: Vec<RistrettoPoint>,p: Vec<RistrettoPoint>,maptypes: Vec<RistrettoPoint>,mapprop: Vec<Vec<RistrettoPoint>>, genmaster: RistrettoPoint,genplayers: Vec<RistrettoPoint>,pcplayers: Vec<Vec<RistrettoPoint>>,pg: Vec<RistrettoPoint>,proof0: Proofgame0,proof1: Proofgame1,proof2: Vec<Proofgame2>, proof3: Vec<Proofgame3>) -> (bool,bool,bool,bool){
   
    let n = maptypes.len();
    
    let mut b0 = true;
    let mut b1 = true;
    let mut b2 = true;
    let mut b3 = true;
   
    // Proof 0
    //sum el
    let mut sumc1 = RistrettoPoint::identity(); // c1 associated with tj pj
    let mut sumc2 = RistrettoPoint::identity(); // c2	
    let mut k = 3; // pg[0] = pk , pg[1] = c10, pg[2] = c20
    while k < 2*(p.len())+3{
        sumc1 += pg[k]; 
        sumc2 += pg[k+1]; 
        k += 2;
    }
    //sum pi for all cell_i
    let mut sumi: Vec<RistrettoPoint> = Vec::new();
    for i in 0..n{
       let mut sum = RistrettoPoint::identity();
       for l in 0..14{
	   sum += mapprop[i][l]; // hi = p1i +... p14i
       }
       sumi.push(sum); // sum(cell_i)
    }
    
    let ghl = vec![sumc1;n];
    let mut yhl = init_vec_ris(n);
    for i in 0..n{
        yhl[i] = sumc2 - sumi[i];
    }
    
    let ge0 = vec![pg[1];n];
    let mut ye0 = init_vec_ris(n);
    for i in 0..n{
    	ye0[i] = pg[2] - maptypes[i];
    }
	
    match proof0{
        Proofgame0{r_0, r_1, r_2, c_c, z_z} => { 
            if verify_game0(pg[0], yhl, ye0, genmaster, ghl, ge0, r_0, r_1, r_2, c_c, z_z) == false{
                b0 = false;
            }
        }
    } 
    
    // Proof 1
    let mut c1l: Vec<RistrettoPoint> = Vec::new();
    let mut c2pl: Vec<RistrettoPoint> = Vec::new();
    let mut c2l: Vec<RistrettoPoint> = Vec::new();
    let mut k = 3;
    while k < 2*(p.len())+3{
        c1l.push(pg[k]); 
        c2pl.push(pg[k+1]);
        c2l.push(pg[k+1]);
        k += 2;
    }
    for i in 0..p.len(){
        c2pl[i] = c2pl[i] - p[i];
    }
     
    match proof1{
        Proofgame1{r_01, r_1, r_02, r_2, c_1, c_2, z_1, z_2} => { 
            if verify_game1(pg[0], (&c2pl).to_vec(), (&c2l).to_vec(), genmaster,(&c1l).to_vec(), (&c1l).to_vec(), r_01, r_1, r_02, r_2, c_1,c_2, z_1,z_2) == false{
                b1 = false;
            }
        }
    }   
    
    for player in 0..genplayers.len(){
    
        // Proof 2 	
        let mut y: Vec<RistrettoPoint> = Vec::new();
        let mut g: Vec<RistrettoPoint> = Vec::new();
        let mut h: Vec<RistrettoPoint> = Vec::new();
    	
    	y.push(pg[2]-pcplayers[player][2]);
    	y.push(pg[2]-pcplayers[player][4]);
    	
    	g.push(pg[1]);
    	g.push(pg[1]);
    	
    	h.push(-pcplayers[player][1]);
    	h.push(-pcplayers[player][3]);
    	
    	let mut l = 3;
    	while l < pg.len(){
    	    y.push(pg[l+1]-pcplayers[player][6]);
    	    h.push(-pcplayers[player][5]);
   	    g.push(pg[l]); 	    
    	    l +=2;
    	}
    	let proof2player = &proof2[player];
 
        match proof2player{
            Proofgame2{r_0,r_a, r_1,r_2,c_c,z_1,z_2} => {
                if verify_game2(pg[0], pcplayers[player][0],y,genmaster,genplayers[player],g,h,(&r_0).to_vec(),(&r_a).to_vec(),(&r_1).to_vec(),(&r_2).to_vec(),(&c_c).to_vec(),(&z_1).to_vec(),(&z_2).to_vec()) == false{
                    b2 = false;
                }
            }
        }
        
        // Proof 3 
        let bottom = RISTRETTO_BASEPOINT_POINT;
            
        let y0 = pcplayers[player][0];
        let g0 = genplayers[player];
        let y1 = pcplayers[player][6] - bottom;
        let g1 = pcplayers[player][5];
        let y2 = pcplayers[player][2] - pcplayers[player][4];  // same as y5
        let g2 = pcplayers[player][1] - pcplayers[player][3]; // same as g5
      	
        let mut y3: Vec<RistrettoPoint> = Vec::new();
        let mut g3: Vec<RistrettoPoint> = Vec::new();
        let mut y4: Vec<RistrettoPoint> = Vec::new();
        let mut g4: Vec<RistrettoPoint> = Vec::new();       
        
        for i in 0..t.len(){
            y3.push(pcplayers[player][2]-t[i]);
            y4.push(pcplayers[player][4]-t[i]); 
            g3.push(pcplayers[player][1]);
            g4.push(pcplayers[player][3]);
        }
        
        let y6 = pcplayers[player][4] - bottom;
        let g6 = pcplayers[player][3];
        
        let mut y7: Vec<RistrettoPoint> = Vec::new();
        let mut g7: Vec<RistrettoPoint> = Vec::new();
        
        for k in 0..p.len(){
            y7.push(pcplayers[player][6]-p[k]);
            g7.push(pcplayers[player][5]);
        }
        
        let proof3player = &proof3[player];
        
        match proof3player{
            Proofgame3{y_0_p,y_1_p,y_2_p,r_00, s_00, r_1, s_1, r_2, s_2, r_03,r_3, r_04, r_4,r_056, r_5, r_6, r_07, r_7,c_00, c_01, c_3, c_4,c_7, u_u, v_v, z_3, z_4,z_056, z_7}=> {
                if verify_game3(y0,y1,y2,y3,y4,y2,y6,y7,g0,g1,g2,g3,g4,g2,g6,g7,*y_0_p,*y_1_p,*y_2_p,*r_00, *s_00, *r_1, *s_1, *r_2, *s_2, (&r_03).to_vec(),(&r_3).to_vec(),(&r_04).to_vec(),(&r_4).to_vec(),*r_056, *r_5, *r_6,(&r_07).to_vec(), (&r_7).to_vec(),*c_00, *c_01,(&c_3).to_vec(),(&c_4).to_vec(),(&c_7).to_vec(), *u_u, *v_v,(&z_3).to_vec(),(&z_4).to_vec(),*z_056,(&z_7).to_vec()) == false{
                    b3 = false;
                }
            }
        }          
    }
    return (b0, b1, b2, b3);  
}

pub fn provegame0<T:CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y1: Vec<RistrettoPoint>,y2: Vec<RistrettoPoint>,g0: RistrettoPoint,g1: Vec<RistrettoPoint>,g2: Vec<RistrettoPoint>,x: Scalar) -> Proofgame0 {

    let mut k = 0;
    while k < y1.len() && (y1[k] != x * g1[k] || y2[k] != x * g2[k]){ // y2 = x * g2 && y1 = x* g1
        k = k + 1;
    }
    let mut w = k;
    if w == y1.len(){
        w = w - 1;
    }
    
    // commit
    let rr = random_scalar(csprng); // random
    let mut r0 = init_vec_ris(y1.len());
    let mut r1 = init_vec_ris(y1.len());
    let mut r2 = init_vec_ris(y2.len());
    
    
    let rr = random_scalar(csprng);
    r2[w] = rr * g2[w]; // w = index j
    r1[w] = rr * g1[w]; // w = index j
    r0[w] = rr * g0;
    
    // simulation
    let mut c = init_vec_scal(y1.len());  
    let mut z = init_vec_scal(y1.len());
    let respsim = simul_game0(csprng,y0,g0,(&y1).to_vec(),(&g1).to_vec(),(&y2).to_vec(),(&g2).to_vec(),(&r0).to_vec(),(&r1).to_vec(),(&r2).to_vec(),(&c).to_vec(),(&z).to_vec(),w);
    r0 = respsim.0;
    r1 = respsim.1;
    r2 = respsim.2;
    c = respsim.3;
    z = respsim.4;
    
    // challenge
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.extend((&r0).to_vec());
    conc.extend((&r1).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());

    let cc = hash_vec(conc); // general challenge
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum = sum + chall;
    }
    c[w] = cc - sum;
    
    // response
    z[w] = rr + c[w] * x;

    return Proofgame0{r_0: r0, r_1: r1, r_2: r2, c_c: c, z_z: z}; 
} 

pub fn simul_game0<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,g0: RistrettoPoint,y1: Vec<RistrettoPoint>,g1: Vec<RistrettoPoint>,y2: Vec<RistrettoPoint>,g2: Vec<RistrettoPoint>,mut r0: Vec<RistrettoPoint>,mut r1: Vec<RistrettoPoint>,mut r2: Vec<RistrettoPoint>,mut c: Vec<Scalar>,mut z: Vec<Scalar>,w: usize) -> (Vec<RistrettoPoint>,Vec<RistrettoPoint>,Vec<RistrettoPoint>,Vec<Scalar>,Vec<Scalar>){  
 
    for k in 0..y1.len(){
        if k != w {
            c[k] = random_scalar(csprng);
            z[k] = random_scalar(csprng);
            r1[k] = z[k] * g1[k] - c[k] * y1[k];   
            r2[k] = z[k] * g2[k] - c[k] * y2[k];
            r0[k] = z[k] * g0 - c[k] * y0;  
        }
    }
    return(r0,r1,r2,c,z)
}
	
pub fn verify_game0(y0: RistrettoPoint, y1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>,r0: Vec<RistrettoPoint>, r1: Vec<RistrettoPoint>, r2: Vec<RistrettoPoint>, c: Vec<Scalar>, z: Vec<Scalar>) -> bool{

    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.extend((&r0).to_vec());
    conc.extend((&r1).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());
    
    let cc = hash_vec(conc);
    
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum += chall;
    }
    
    if cc == sum{
    	for l in 0..y1.len(){
    	    if z[l] * g1[l] != r1[l] + c[l] * y1[l] || z[l] * g2[l] != r2[l] + c[l] * y2[l] || z[l] * g0 != r0[l] + c[l] * y0{
    	        return false;
    	    }
        }
        return true;
    }
    else{
        return false;
    }
}
  
pub fn provegame1<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y1: Vec<RistrettoPoint>,y2: Vec<RistrettoPoint>,g0: RistrettoPoint,g1: Vec<RistrettoPoint>,g2: Vec<RistrettoPoint>,x: Scalar) -> Proofgame1{

    // commit   
    let mut r01 = init_vec_ris(y1.len());
    let mut r02 = init_vec_ris(y2.len());
    let mut r1 = init_vec_ris(y1.len());
    let mut r2 = init_vec_ris(y2.len());
    let mut c1 = init_vec_scal(y1.len());
    let mut c2 = init_vec_scal(y2.len());
    let mut z1 = init_vec_scal(y1.len());
    let mut z2 = init_vec_scal(y2.len());
    
    let mut rrr: Vec<Scalar> = Vec::new();
    
    for l in 0..14{
    	if y1[l] == x * g1[l]{ // send other to the simulator
    	    let rr1 = random_scalar(csprng);
    	    r01[l] = rr1 * g0; 
    	    r1[l] = rr1 * g1[l]; 
    	    rrr.push(rr1);
    	    let respsim = simul_game1(csprng,y0,y2[l],g0,g2[l]);
    	    r02[l] = respsim.0; 
    	    r2[l] = respsim.1;
    	    c2[l] = respsim.2;
    	    z2[l] = respsim.3;       
    	}
    	else{ // y2[l] == x * g2[l] or proof false
    	
    	    let rr2 = random_scalar(csprng);
    	    r02[l] = rr2 * g0; 
    	    r2[l] = rr2 * g2[l]; 
    	    rrr.push(rr2);
    	    let respsim = simul_game1(csprng,y0,y1[l],g0,g1[l]);
    	    r01[l] = respsim.0; 
    	    r1[l] = respsim.1; 
    	    c1[l] = respsim.2;
    	    z1[l] = respsim.3; 
    	}
    }
    
    // challenge
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    
    conc.extend((&r01).to_vec());
    conc.extend((&r1).to_vec());
    conc.extend((&r01).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());
    
    let cc = hash_vec(conc);

    for l in 0..14{
    	if y1[l] == x * g1[l]{ 
    	    c1[l] = cc - c2[l]; 
    	    // response
	    z1[l] = rrr[l] + c1[l] * x;         
    	}
    	else{ // y1[l] == x * g1[l] or proof false
    	    c2[l] = cc - c1[l]; 
    	    // response
	    z2[l] = rrr[l] + c2[l] * x; 
    	}
    }
    return Proofgame1{r_01: r01, r_1: r1, r_02: r02, r_2: r2, c_1: c1, c_2: c2, z_1: z1, z_2: z2}
}
    
pub fn simul_game1<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: RistrettoPoint,g0: RistrettoPoint,g: RistrettoPoint) -> (RistrettoPoint,RistrettoPoint, Scalar, Scalar){
    let c = random_scalar(csprng);
    let z = random_scalar(csprng);
    let r = z * g - c * y;
    let r0 = z * g0 - c * y0;
    return(r0,r,c,z)
}

pub fn verify_game1(y0: RistrettoPoint,y1: Vec<RistrettoPoint>,y2: Vec<RistrettoPoint>,g0: RistrettoPoint,g1: Vec<RistrettoPoint>,g2: Vec<RistrettoPoint>,r01: Vec<RistrettoPoint>,r1: Vec<RistrettoPoint>,r02: Vec<RistrettoPoint>,r2: Vec<RistrettoPoint>,c1: Vec<Scalar>,c2: Vec<Scalar>,z1: Vec<Scalar>,z2:Vec<Scalar>) -> bool{
    
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.extend((&r01).to_vec());
    conc.extend((&r1).to_vec());
    conc.extend((&r01).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());
    
    let cc = hash_vec(conc);
    
    for l in 0..y1.len(){
    	if cc != c1[l] + c2[l] || z1[l] * g1[l] != r1[l] + c1[l] * y1[l] || z2[l] * g2[l] != r2[l] + c2[l] * y2[l] || z1[l] * g0 != r01[l] + c1[l] * y0 || z2[l] * g0 != r02[l] + c2[l] * y0{
    	    return false
    	    
    	}
    	return true
    }
    return false
}

pub fn provegame2<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,ya: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,ga:RistrettoPoint,g: Vec<RistrettoPoint>,h: Vec<RistrettoPoint>,x: Scalar,xa: Scalar) -> Proofgame2{
    
    let mut k = 0;
    while k < y.len() && (y[k] != x * g[k] + xa * h[k]){ // y = g^x . h^xa
        k = k + 1;
    }
    let mut w = k; // if we don't find the correct index
    if w == y.len(){
        w = w - 1;
    }  
    
    let mut r = init_vec_ris(y.len());
    let mut s = init_vec_ris(y.len());
    let mut r0 = init_vec_ris(y.len());
    let mut ra = init_vec_ris(y.len());
    
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);
    r0[w] = rr * g0;
    ra[w] = ss * ga;
    r[w] = rr * g[w];
    s[w] = ss * h[w];
    
    let mut c = init_vec_scal(y.len());
    let mut u = init_vec_scal(y.len());
    let mut v = init_vec_scal(y.len());
      
    //simulator
    let respsim = simul_game2(csprng,y0,ya,(&y).to_vec(),g0,ga,(&g).to_vec(),(&h).to_vec(),(&r0).to_vec(),(&ra).to_vec(),(&r).to_vec(),(&s).to_vec(),(&c).to_vec(),(&u).to_vec(),(&v).to_vec(),w);
    
    r0 = respsim.0;
    ra = respsim.1;
    r = respsim.2;
    s = respsim.3;
    c = respsim.4;
    u = respsim.5;
    v = respsim.6;
    
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum += chall;
    }
    
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.extend((&r0).to_vec());
    conc.extend((&ra).to_vec());
    conc.extend((&r).to_vec());
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.push(ya);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.push(ga);
    conc.extend((&g).to_vec());
    conc.extend((&h).to_vec());
    let cc = hash_vec(conc);
    
    c[w] = cc - sum;
    u[w] = rr + c[w] * x;
    v[w] = ss + c[w] * xa;
    
    return Proofgame2{r_0: r0, r_a: ra, r_1: r, r_2: s, c_c: c, z_1: u, z_2: v};
}
 
pub fn simul_game2<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,ya: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,ga:RistrettoPoint,g: Vec<RistrettoPoint>, h: Vec<RistrettoPoint>,mut r0: Vec<RistrettoPoint>, mut ra: Vec<RistrettoPoint>,mut r: Vec<RistrettoPoint>,mut s: Vec<RistrettoPoint>,mut c: Vec<Scalar>,mut u: Vec<Scalar>,mut v: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>,Vec<RistrettoPoint>, Vec<RistrettoPoint>,Vec<Scalar>, Vec<Scalar>, Vec<Scalar>){

    for i in 0..y.len(){
    	if i != w{
    	    c[i] = random_scalar(csprng);
    	    u[i] = random_scalar(csprng);
    	    v[i] = random_scalar(csprng);
    	    r0[i] = u[i] * g0 - c[i] * y0;
    	    ra[i] = v[i] * ga - c[i] * ya;
    	    r[i] = random_point(csprng);
    	    s[i] = u[i] * g[i] + v[i] * h[i] - (r[i] + c[i] * y[i]);
    	}
    }
    return (r0,ra,r,s,c,u,v)   
}
      
pub fn verify_game2(y0: RistrettoPoint,ya: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,ga:RistrettoPoint,g: Vec<RistrettoPoint>,h: Vec<RistrettoPoint>, r0:Vec<RistrettoPoint>,ra: Vec< RistrettoPoint>,r: Vec<RistrettoPoint>,s: Vec<RistrettoPoint>,c: Vec<Scalar>,u: Vec<Scalar>,v:Vec<Scalar>) -> bool{

    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.extend((&r0).to_vec());
    conc.extend((&ra).to_vec());
    conc.extend((&r).to_vec());
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.push(ya);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.push(ga);
    conc.extend((&g).to_vec());
    conc.extend((&h).to_vec());
    let cc = hash_vec(conc);

    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum += chall;
    }   
    if sum == cc{
    	for i in 0..y.len(){
    	    if r[i] + s[i] != u[i] * g[i] + v[i] * h[i] - c[i] * y[i] || r0[i] != u[i] * g0 - c[i] * y0 || ra[i] != v[i] * ga - c[i] * ya {
    	    	return false;
    	    }
    	}
    	return true;
    }
    else{
        return false; 	
    }
}

pub fn provegame3<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y1: RistrettoPoint,y2: RistrettoPoint, y3: Vec<RistrettoPoint>,y4: Vec<RistrettoPoint>,y5: RistrettoPoint,y6: RistrettoPoint,y7:Vec<RistrettoPoint>,g0: RistrettoPoint,g1: RistrettoPoint,g2: RistrettoPoint, g3: Vec<RistrettoPoint>,g4: Vec<RistrettoPoint>,g5: RistrettoPoint,g6: RistrettoPoint,g7: Vec<RistrettoPoint>,x: Scalar) -> Proofgame3{

    let mut truepart1 = 0;
    let mut truepart3 = 0;
    let mut truepart4 = 0;

    // To determine the true part
    if y0 == x*g0 && y1 == x*g1 && y2 != x*g2{
        truepart1 = 1;
        for l in 0..y3.len(){
            if y3[l] == x*g3[l]{
    	        truepart3 = 1; // at least one is true in the set
    	    } 
    	    if y4[l] == x*g4[l]{
    	        truepart4 = 1;
    	    }   	
        }
    } 
    let truepart = truepart1 * truepart3 * truepart4;
    if truepart == 1 { //the first part is true and the other is send to the simulator 

        // commit
        let bb = random_scalar(csprng);
        let aa = x * bb;
    
        let h0 = -y0;
        let h1 = -y1;
        let h2 = -y2;
    
        let y0_p = aa * g0 + bb * h0;
        let y1_p = aa * g1 + bb * h1;
        let y2_p = aa * g2 + bb * h2;
    
        let rr = random_scalar(csprng);
        let ss = random_scalar(csprng);
    
        // first part of proof
        let r00 = rr * g0;
        let r1 = rr * g1;
        let r2 = rr * g2;
        let s00 = ss * h0;
        let s1 = ss * h1;
        let s2 = ss * h2;  
        
        // simulator for prove "or"
        let respsim3 = prove_or(csprng,y0,(&y3).to_vec(),g0,(&g3).to_vec(),x);
        let mut r03 = respsim3.0;
        let mut r3 = respsim3.1;
        let mut c3 = respsim3.2; // without the challenge for c3[w3] which depend on C00
        let mut z3 = respsim3.3;
        let w3 = respsim3.4;

        let rr3 = random_scalar(csprng);
        r03[w3] = rr3 * g0;
        r3[w3] = rr3 * g3[w3];

        let respsim4 = prove_or(csprng,y0,(&y4).to_vec(),g0,(&g4).to_vec(),x);       
        let mut r04 = respsim4.0;
        let mut r4 = respsim4.1;
        let mut c4 = respsim4.2;
        let mut z4 = respsim4.3;
        let w4 = respsim4.4;
    
        let rr4 = random_scalar(csprng);
        r04[w4] = rr4 * g0;
        r4[w4] = rr4 * g4[w4];
        
        
        // second part of proof
        let c01 = random_scalar(csprng);
        let z056 = random_scalar(csprng);
        
        let r5 = z056 * g5 - c01 * y5;
        let r056 = z056 * g0 - c01 * y0;
        let r6 = z056 * g6 - c01 * y6;
     
        let mut c7: Vec<Scalar> = Vec::new();
        let mut z7: Vec<Scalar> = Vec::new();
        
        let mut r07: Vec<RistrettoPoint> = Vec::new();
        let mut r7: Vec<RistrettoPoint> = Vec::new();
        
        let mut sum7 = convert_scalar([0u8;32]);
        
        for l in 0..y7.len()-1{
            c7.push(random_scalar(csprng));
            z7.push(random_scalar(csprng));
            sum7 += c7[l];
            r07.push(z7[l] * g0 - c7[l] * y0);
            r7.push(z7[l] * g7[l] - c7[l] * y7[l]);      
        }
        
        c7.push(c01 - sum7);
        z7.push(random_scalar(csprng));
        r07.push(z7[y7.len()-1] * g0 - c7[y7.len()-1] * y0);
        r7.push(z7[y7.len()-1] * g7[y7.len()-1] - c7[y7.len()-1] * y7[y7.len()-1]); 
        
        // challenge 
        let mut conc: Vec<RistrettoPoint> = Vec::new();
        conc.push(r00);
        conc.push(r1);
        conc.push(r2);
        conc.push(s00);
        conc.push(s1);
        conc.push(s2);
        conc.extend((&r03).to_vec());
        conc.extend((&r3).to_vec());
        conc.extend((&r04).to_vec());
        conc.extend((&r4).to_vec());
        conc.push(r056);
        conc.push(r5);
        conc.push(r6);
        conc.extend((&r07).to_vec());
        conc.extend((&r7).to_vec());
        conc.push(y0);
        conc.push(y1);
        conc.push(y2);
        conc.extend((&y3).to_vec());
        conc.extend((&y4).to_vec());
        conc.push(y5);
        conc.push(y6);
        conc.extend((&y7).to_vec());
        conc.push(y0_p);
        conc.push(y1_p);
        conc.push(y2_p);
        conc.push(g0);
        conc.push(g1);
        conc.push(g2);
        conc.push(h0);
        conc.push(h1);
        conc.push(h2);
        conc.extend((&g3).to_vec());
        conc.extend((&g4).to_vec());
        conc.push(g5);
        conc.push(g6);
        conc.extend((&g7).to_vec());
        let cc = hash_vec(conc);
        
        let c00 = cc - c01;
        
        let uu = rr + c00 * x;
        let vv = ss + c00 * x;
   
        let mut sum3 = convert_scalar([0u8;32]);
        for chall in &c3{
            sum3 += chall;
        }  
        c3[w3] = c00 - sum3;

        let mut sum4 = convert_scalar([0u8;32]);
        for chall in &c4{
            sum4 += chall;
        } 
        c4[w4] = c00 - sum4;   
        
        // response
        z3[w3] = rr3 + c3[w3]*x;
        z4[w4] = rr4 + c4[w4]*x;
        let uu = rr + c00 * aa; 
        let vv = ss + c00 * bb;
            
        return Proofgame3{y_0_p: y0_p, y_1_p: y1_p, y_2_p: y2_p, r_00: r00, s_00: s00, r_1: r1, s_1: s1, r_2: r2, s_2: s2, r_03: r03, r_3: r3, r_04: r04, r_4: r4, r_056: r056, r_5: r5, r_6: r6, r_07: r07, r_7: r7,c_00: c00, c_01: c01, c_3: c3, c_4: c4, c_7: c7, u_u: uu, v_v: vv, z_3: z3, z_4: z4, z_056: z056, z_7: z7};
        
    }
    else{ // the second part is true or return a false proof
        
        //commit
        // simulates the first part
        let y0_p = RistrettoPoint::identity();
        let y1_p = RistrettoPoint::identity();
        let mut y2_p = random_point(csprng);
        while y2_p == RistrettoPoint::identity(){
            y2_p = random_point(csprng);
        }
        
        let h0 = -y0;
        let h1 = -y1;
        let h2 = -y2;
        
        let s00 = random_point(csprng);
        let s1 = random_point(csprng);
        let s2 = random_point(csprng);
        
        let uu = random_scalar(csprng);
        let vv = random_scalar(csprng);
        
        let c00 = random_scalar(csprng);
        let r00 = uu * g0 + vv * h0 - s00 - c00 * y0_p;
        let r1 = uu * g1 + vv * h1 - s1 - c00 * y1_p;
        let r2 = uu * g2 + vv * h2 - s2 - c00 * y2_p;
        
        let mut c3: Vec<Scalar> = Vec::new();
        let mut z3: Vec<Scalar> = Vec::new();
        
        let mut r03: Vec<RistrettoPoint> = Vec::new();
        let mut r3: Vec<RistrettoPoint> = Vec::new();
        
        let mut sum3 = convert_scalar([0u8;32]);
        
        for l in 0..y3.len()-1{
            c3.push(random_scalar(csprng));
            z3.push(random_scalar(csprng));
            sum3 += c3[l];
            r03.push(z3[l] * g0 - c3[l] * y0);
            r3.push(z3[l] * g3[l] - c3[l] * y3[l]);      
        }
        
        c3.push(c00 - sum3);
        z3.push(random_scalar(csprng));
        r03.push(z3[y3.len()-1] * g0 - c3[y3.len()-1] * y0);
        r3.push(z3[y3.len()-1] * g3[y3.len()-1] - c3[y3.len()-1] * y3[y3.len()-1]); 
        
        
        let mut c4: Vec<Scalar> = Vec::new();
        let mut z4: Vec<Scalar> = Vec::new();
        
        let mut r04: Vec<RistrettoPoint> = Vec::new();
        let mut r4: Vec<RistrettoPoint> = Vec::new();
        
        let mut sum4 = convert_scalar([0u8;32]);
        
        for l in 0..y4.len()-1{
            c4.push(random_scalar(csprng));
            z4.push(random_scalar(csprng));
            sum4 += c4[l];
            r04.push(z4[l] * g0 - c4[l] * y0);
            r4.push(z4[l] * g4[l] - c4[l] * y4[l]);      
        }
        
        c4.push(c00 - sum4);
        z4.push(random_scalar(csprng));
        r04.push(z4[y4.len()-1] * g0 - c4[y4.len()-1] * y0);
        r4.push(z4[y4.len()-1] * g4[y4.len()-1] - c4[y4.len()-1] * y4[y4.len()-1]); 
        
        // second part of proof
        let rr = random_scalar(csprng);
        let r056 = rr * g0;
        let r5 = rr * g5;
        let r6 = rr * g6;

        let respsim7 = prove_or(csprng,y0,(&y7).to_vec(),g0,(&g7).to_vec(),x);       
        let mut r07 = respsim7.0;
        let mut r7 = respsim7.1;
        let mut c7 = respsim7.2;
        let mut z7 = respsim7.3;
        let w7 = respsim7.4;
    
        let rr7 = random_scalar(csprng);
        r07[w7] = rr7 * g0;
        r7[w7] = rr7 * g7[w7];
        
        // challenge
        let mut conc: Vec<RistrettoPoint> = Vec::new();
        conc.push(r00);
        conc.push(r1);
        conc.push(r2);
        conc.push(s00);
        conc.push(s1);
        conc.push(s2);
        conc.extend((&r03).to_vec());
        conc.extend((&r3).to_vec());
        conc.extend((&r04).to_vec());
        conc.extend((&r4).to_vec());
        conc.push(r056);
        conc.push(r5);
        conc.push(r6);
        conc.extend((&r07).to_vec());
        conc.extend((&r7).to_vec());
        conc.push(y0);
        conc.push(y1);
        conc.push(y2);
        conc.extend((&y3).to_vec());
        conc.extend((&y4).to_vec());
        conc.push(y5);
        conc.push(y6);
        conc.extend((&y7).to_vec());
        conc.push(y0_p);
        conc.push(y1_p);
        conc.push(y2_p);
        conc.push(g0);
        conc.push(g1);
        conc.push(g2);
        conc.push(h0);
        conc.push(h1);
        conc.push(h2);
        conc.extend((&g3).to_vec());
        conc.extend((&g4).to_vec());
        conc.push(g5);
        conc.push(g6);
        conc.extend((&g7).to_vec());
        let cc = hash_vec(conc);
        
        let c01 = cc - c00;
        
        let mut sum7 = convert_scalar([0u8;32]);
        for chall in &c7{
            sum7 += chall;
        }  
        c7[w7] = c01 - sum7;
        
        // response
        let z056 = rr + c01 * x;
        z7[w7] = rr7 + c7[w7] * x;
        
        return Proofgame3{y_0_p: y0_p, y_1_p: y1_p, y_2_p: y2_p, r_00: r00, s_00: s00, r_1: r1, s_1: s1, r_2: r2, s_2: s2, r_03: r03, r_3: r3, r_04: r04, r_4: r4, r_056: r056, r_5: r5, r_6: r6, r_07: r07, r_7: r7, c_00: c00, c_01: c01, c_3: c3, c_4: c4, c_7: c7, u_u: uu, v_v: vv, z_3: z3, z_4: z4, z_056: z056, z_7: z7};
    }
}
           
pub fn verify_game3(y0: RistrettoPoint,y1: RistrettoPoint,y2: RistrettoPoint, y3: Vec<RistrettoPoint>,y4: Vec<RistrettoPoint>,y5: RistrettoPoint,y6: RistrettoPoint,y7:Vec<RistrettoPoint>,g0: RistrettoPoint,g1: RistrettoPoint,g2: RistrettoPoint, g3: Vec<RistrettoPoint>,g4: Vec<RistrettoPoint>,g5: RistrettoPoint,g6: RistrettoPoint,g7: Vec<RistrettoPoint>,y0_p: RistrettoPoint,y1_p: RistrettoPoint,y2_p: RistrettoPoint,r00: RistrettoPoint, s00: RistrettoPoint, r1: RistrettoPoint, s1: RistrettoPoint, r2: RistrettoPoint, s2: RistrettoPoint, r03: Vec<RistrettoPoint>,r3: Vec<RistrettoPoint>, r04: Vec<RistrettoPoint>,r4: Vec<RistrettoPoint>,r056: RistrettoPoint, r5: RistrettoPoint, r6: RistrettoPoint, r07: Vec<RistrettoPoint>, r7: Vec<RistrettoPoint>,c00: Scalar, c01: Scalar, c3: Vec<Scalar>, c4: Vec<Scalar>,c7 : Vec<Scalar>, uu: Scalar, vv: Scalar, z3: Vec<Scalar>, z4: Vec<Scalar>,z056: Scalar, z7: Vec<Scalar>) -> bool{
  
    let h0 = -y0;
    let h1 = -y1;
    let h2 = -y2;
    
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r00);
    conc.push(r1);
    conc.push(r2);
    conc.push(s00);
    conc.push(s1);
    conc.push(s2);
    conc.extend((&r03).to_vec());
    conc.extend((&r3).to_vec());
    conc.extend((&r04).to_vec());
    conc.extend((&r4).to_vec());
    conc.push(r056);
    conc.push(r5);
    conc.push(r6);
    conc.extend((&r07).to_vec());
    conc.extend((&r7).to_vec());
    conc.push(y0);
    conc.push(y1);
    conc.push(y2);
    conc.extend((&y3).to_vec());
    conc.extend((&y4).to_vec());
    conc.push(y5);
    conc.push(y6);
    conc.extend((&y7).to_vec());
    conc.push(y0_p);
    conc.push(y1_p);
    conc.push(y2_p);
    conc.push(g0);
    conc.push(g1);
    conc.push(g2);
    conc.push(h0);
    conc.push(h1);
    conc.push(h2);
    conc.extend((&g3).to_vec());
    conc.extend((&g4).to_vec());
    conc.push(g5);
    conc.push(g6);
    conc.extend((&g7).to_vec());
    let cc = hash_vec(conc);
        
    let mut sum3 = convert_scalar([0u8;32]);
    for chall in &c3{
        sum3 += chall;
    }      
    let mut sum4 = convert_scalar([0u8;32]);
    for chall in &c4{
        sum4 += chall;
    }      
    let mut sum7 = convert_scalar([0u8;32]);
    for chall in &c7{
        sum7 += chall;
    }               
    if cc != c00+c01 || c00 != sum3 && c00 != sum4 || c01 != sum7 || y0_p != RistrettoPoint::identity() || y1_p != RistrettoPoint::identity() || y2_p == RistrettoPoint::identity(){
        return false
    }   
    if r00 + s00 != uu * g0 + vv * h0 - c00 * y0_p || r1 + s1 != uu * g1 + vv * h1 - c00 * y1_p || r2 + s2 != uu * g2 + vv * h2 - c00 * y2_p{
        return false;      
    }
    for l in 0..y3.len(){
 	if r03[l] != z3[l] * g0 - c3[l] * y0 || r3[l] != z3[l] * g3[l] - c3[l] * y3[l]{
 	    return false;
 	}
    }
    for l in 0..y4.len(){
 	if r04[l] != z4[l] * g0 - c4[l] * y0 || r4[l] != z4[l] * g4[l] - c4[l] * y4[l]{
 	    return false;
 	}
    }	
    if r056 != z056 * g0 - c01 * y0 || r5 != z056 * g5 - c01 * y5 || r6 != z056 * g6 - c01 * y6{
 	return false;
    }
 	
    for l in 0..y7.len(){
 	if r07[l] != z7[l] * g0 - c7[l] * y0 || r7[l] != z7[l] * g7[l] - c7[l] * y7[l]{
 	    return false;
        }
    } 
    return true;
}

pub fn prove_or<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>,x: Scalar) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>,Vec<Scalar>, Vec<Scalar>,usize) {
    
    let mut k = 0;
    while k < y.len() && (y[k] != x * g[k]){ // y = g^x . h^xa
        k = k + 1;
    }
    let mut w = k; // if we don't find the correct index
    if w == y.len(){
        w = w - 1;
    }
   
    let mut r0 = init_vec_ris(y.len());
    let mut r = init_vec_ris(y.len());
    let mut z = init_vec_scal(y.len());
    let mut c = init_vec_scal(y.len());
    
    let respsim = simul_or(csprng,y0,(&y).to_vec(),g0,(&g).to_vec(),(&r0).to_vec(),(&r).to_vec(),(&c).to_vec(),(&z).to_vec(),w);
    
    r0 = respsim.0;
    r = respsim.1;
    c = respsim.2;
    z = respsim.3;
    
    return (r0,r,c,z,w);
}

pub fn simul_or<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>,mut r0: Vec<RistrettoPoint>, mut r: Vec<RistrettoPoint>,mut c: Vec<Scalar>,mut z: Vec<Scalar>,w: usize) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>,Vec<Scalar>, Vec<Scalar>){ 
    
    for i in 0..y.len(){
        if i != w{
            z[i] = random_scalar(csprng);
    	    c[i] = random_scalar(csprng);
    	    r0[i] = z[i] * g0 - c[i] * y0;
    	    r[i] = z[i] * g[i] - c[i] * y[i];
        }
    }
    return(r0,r,c,z);
}

