use rand_core::{CryptoRng, RngCore};
use rand::{Rng, distributions::{Distribution, Uniform}};
use std::{time::Duration, time::Instant, io, io::Write, fs::File, fs};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity, constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;

// Definition of structures for the proofs.
#[derive(Debug)]
pub enum Proof{
    ProofMaybe{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, c_1: Vec<Scalar>, z_0: Scalar, z_1: Vec<Scalar>},
    ProofNo{y_0_p: RistrettoPoint, y_1_p: Vec<RistrettoPoint>, r_0: RistrettoPoint, r_r: Vec<RistrettoPoint>, s_0: RistrettoPoint, s_s: Vec<RistrettoPoint>, u_u: Scalar, v_v: Scalar},
    Error{err: bool},
}

#[derive(Debug)]
pub struct Proofgame0{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, r_2: Vec<RistrettoPoint>, c_c: Vec<Scalar>, z_0: Scalar, z_z: Vec<Scalar>}
 
#[derive(Debug)]   
pub struct Proofgame1{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, r_2: Vec<RistrettoPoint>, c_1: Vec<Scalar>, c_2: Vec<Scalar>, z_0: Scalar, z_1: Vec<Scalar>, z_2: Vec<Scalar>}

#[derive(Debug)]
pub struct Proofgame2{r_0: RistrettoPoint, r_a: RistrettoPoint, r_1: Vec<RistrettoPoint>, r_2: Vec<RistrettoPoint>, c_c: Vec<Scalar>, z_0: Scalar, z_a: Scalar, z_1: Vec<Scalar>, z_2: Vec<Scalar>}

#[derive(Debug)]
pub struct Proofgame3{y_1_p: RistrettoPoint, y_2_p: RistrettoPoint, r_0: RistrettoPoint, r_1: RistrettoPoint, s_1: RistrettoPoint, r_2: RistrettoPoint, s_2: RistrettoPoint, r_3: Vec<RistrettoPoint>, r_4: Vec<RistrettoPoint>, r_5: RistrettoPoint, r_6: RistrettoPoint, r_7: Vec<RistrettoPoint>, c_00: Scalar, c_01: Scalar, c_3: Vec<Scalar>, c_4: Vec<Scalar>, c_7: Vec<Scalar>, z_0: Scalar, u_u: Scalar, v_v: Scalar, z_3: Vec<Scalar>, z_4: Vec<Scalar>, z_56: Scalar, z_7: Vec<Scalar>}

// It generates a random scalar (given in the curve25519_dalek library).
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// It generates a random RistrettoPoint.
pub fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// It converts a [u8; 32] in Scalar.
fn convert_scalar(a: [u8; 32]) -> Scalar{
    
    let s = Scalar::from_bytes_mod_order(a);
    return s
}	       

// It converts a RistrettoPoint in [u8; 32].
fn convert_ristretto(t: RistrettoPoint) -> [u8; 32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption/Decryption.
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint, Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
pub fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint, pk: RistrettoPoint, m: RistrettoPoint)-> (RistrettoPoint, RistrettoPoint){ 
	
    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1, c2)
}
	
fn dec_elgamal(sk: Scalar, c1: RistrettoPoint, c2: RistrettoPoint)-> RistrettoPoint{ 

    let m = c2 - sk * c1 ;
    return m
}
	
// It hashes and concatenates a RistrettoPoint vector.
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8; 32]> = Vec::new();	
    for p in input {
	let p_p = convert_ristretto(p);
	k.push(p_p);
    }
    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8; 32]>::from_hex(h);
    let mut u = [0u8; 32];
        
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }   
    return convert_scalar(u);      
}
 
// It initializes a vector of size t. 
fn init_vec_ristretto(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity(); t];
    return vec
}

fn init_vec_scalar(t: usize) -> Vec<Scalar> {
    
    let vec = vec![convert_scalar([0u8; 32]); t];
    return vec
}
    	   
// Generation of types, properties, map, cells and clues.
// Generation of random Ristretto group elements for defining the types and the properties.
pub fn typesandproperties<T: CryptoRng + RngCore>(csprng: &mut T) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>, RistrettoPoint){
    
    let mut t: Vec<RistrettoPoint> = Vec::new();
    let mut p: Vec<RistrettoPoint> = Vec::new();
    let bottom = random_point(csprng);
	
    // It generates the five types.
    let mut k = 0;
    while k < 5{
        let mut ti = random_point(csprng);
        while ti == bottom || ti == RistrettoPoint::identity() || t.contains(&ti){
            ti = random_point(csprng);
        }
        t.push(ti);
        k = k + 1;
    }
    
    // It generates the fourteen properties.
    k = 0;
    while k < 14{
        let mut pi = random_point(csprng);
        while pi == bottom || pi == RistrettoPoint::identity() || t.contains(&pi) || p.contains(&pi) {
            pi = random_point(csprng);
        }
        p.push(pi);
        k = k + 1;
    }
    return(t, p, bottom)
}

//It generates a specific cell. w gives the index of types and x is the set of the index of properties for the cell.
pub fn gencell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, w: usize, mut x: Vec<usize>) -> (RistrettoPoint, Vec<RistrettoPoint>){
    
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
        }
    }
    return(ti, pi)
}

// It generates a random cell. n is the number of properties of the cell.
pub fn randomcell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, n: usize) -> (RistrettoPoint, Vec<RistrettoPoint>){
     
    let between5 = Uniform::from(0..5); 
    let mut rng = rand::thread_rng();  
    let w = between5.sample(&mut rng);
    let mut x:  Vec<usize> = Vec::new();   
    let mut k = 0;
    while k < n{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let z = between14.sample(&mut rng);
        if x.contains(&z){
            continue;
        }
        else {
            x.push(z);
        }
        k = k + 1;    
    }
    let ci = gencell(t, p, w, x);
    return ci
}

// It builds a random clue:
// We build two random clues for which the player answer is "maybe" for the jth cell.
// i = 0 corresponds to a clue of the form (Tj, Tk, bottom) or (Tk, Tj, bottom) where Tj =/= Tk,
// i = 1 corresponds to a clue of the form (bottom, bottom, P) where P belongs to Pj,
// and we build two second other forms of clue for which the player answer is "no" for the jth cell. 
// i = 2 corresponds to (Ti, Tk, bottom) where Ti =/= Tj and Tk =/= Tj,
// i = 3 corresponds to (bottom, bottom, P) where P is does not belong to Pj.
pub fn buildclue(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, i: usize) -> Vec<RistrettoPoint>{
    
    if i == 0{
        let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r1 = between5.sample(&mut rng);
        while t[r1] == tj{
    	    r1 = between5.sample(&mut rng);  
        }
        let r = rng.gen_bool(0.5);
        if r == true{
            return vec![tj, t[r1], bottom];
        }
        else{
            return vec![t[r1], tj, bottom];
        }
    }
    if i == 1{
        let betweenpj = Uniform::from(0..pj.len()); 
        let mut rng = rand::thread_rng();  
        let mut r = betweenpj.sample(&mut rng);
        while pj[r] == RistrettoPoint::identity(){
             r = betweenpj.sample(&mut rng);
        }
        return vec![bottom, bottom, pj[r]];
    }    
    if i == 2{
    	let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r1 = between5.sample(&mut rng);
        let mut r2 = between5.sample(&mut rng);

    	while t[r1] == tj || t[r2] == tj || t[r1] == t[r2]{
            r1 = between5.sample(&mut rng);
    	    r2 = between5.sample(&mut rng);
    	}
    	return vec![t[r1], t[r2], bottom];
    }
    else{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let mut r = between14.sample(&mut rng);
    	while pj.contains(&p[r]){
    	    r = between14.sample(&mut rng);
   	}
   	return vec![bottom, bottom, p[r]];
    }
}

// It generates a set of clues for the players.
pub fn buildplayerclues(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, tj : RistrettoPoint, pj: Vec<RistrettoPoint>, clueforms: Vec<usize>) -> Vec<Vec<RistrettoPoint>>{
    
    let mut playerclues: Vec<Vec<RistrettoPoint>> = Vec::new();
    for i in clueforms{
        let clue = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
    	playerclues.push(clue);
    }
    return playerclues 	
}

// It generates a set of public clue key and secret clue key for all players.    
pub fn genplayerclues<T: CryptoRng + RngCore>(csprng: &mut T, genplayers: Vec<RistrettoPoint>, playerclues: Vec<Vec<RistrettoPoint>>) -> (Vec<Vec<RistrettoPoint>>, Vec<Scalar>){
   
    let mut pcplayers: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut scplayers: Vec<Scalar> = Vec::new();	
    for i in 0..genplayers.len(){
    	let keyc = genclue(csprng, genplayers[i], (&playerclues[i]).to_vec());
    	pcplayers.push(keyc.0);
    	scplayers.push(keyc.1); 
    }
    return (pcplayers, scplayers)	
}

// It builds a public game master key and a secret game master key.   	
pub fn buildmaster< T: CryptoRng + RngCore>(csprng: &mut T, genmaster: RistrettoPoint, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){
	
    let key = gen_elgamal(csprng, genmaster); // key.0 = genmaster, key.1 = pk and key.2 = sk.
    let mut pg: Vec<RistrettoPoint> = Vec::new();
    pg.push(key.1);
    let e0 = enc_elgamal(csprng, genmaster, pg[0], tj);
    pg.push(e0.0); 
    pg.push(e0.1); 
    for prop in p{
        if pj.contains(&prop){
	    let e = enc_elgamal(csprng, genmaster, pg[0],prop);
	    pg.push(e.0); 
	    pg.push(e.1); 
	}
	else{
	    let e = enc_elgamal(csprng, genmaster, pg[0], RistrettoPoint::identity());
	    pg.push(e.0);
	    pg.push(e.1); 
	}	
    }
    return (pg, key.2)
}

// It builds a set of random cell depending on the types and properties generated. n is the number of cells.
pub fn buildrandommap(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, n: usize) -> (Vec<RistrettoPoint>, Vec<Vec<RistrettoPoint>>){

    let mut maptypes: Vec<RistrettoPoint> = Vec::new();
    let mut mapprop: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut k = 0;
    while k < n{
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13);
        let tj = cj.0;
        let pj = cj.1;
        maptypes.push(tj);
        mapprop.push(pj);
        k = k + 1; 
    }
    return(maptypes, mapprop);
}

// It write the public clue or the proofs in a file.
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

pub fn writeproofgame(pg: Vec<RistrettoPoint>, proof0: &Proofgame0, proof1: &Proofgame1, proof2: &Vec<Proofgame2>, proof3: &Vec<Proofgame3>) -> io::Result<()> {
    let mut file = File::create("proofgame.txt")?;
    file.write_fmt(format_args!("{:?}{:?}{:?}{:?}{:?}", pg, proof0, proof1, proof2, proof3))?;
    return Ok(())
}

// Algorithm GenClue. g0 is the generator used to generate the public key of the player.
pub fn genclue <T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){

    let key = gen_elgamal(csprng, g0); // key.0 = g, key.1 = pk and key.2 = sk.
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue{
        let e = enc_elgamal(csprng, g0, pc[0], c);
	pc.push(e.0); // c1
	pc.push(e.1); // c2	
    }
    return (pc, key.2)
}  

// Algorithm OpenClue.
pub fn openclue(pc: Vec<RistrettoPoint>, sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc, pc[k], pc[k+1]);
        clue.push(c); 
        k += 2;  
    } 
    return clue
}

pub fn algoanswer(bottom: RistrettoPoint, clue: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>) -> usize{
    
    if clue[2] == bottom{
        if clue[0] == tj || clue[1] == tj{ 
            return 1
        }
        else{
            return 0
        }
    }
    if clue[0] == bottom && clue[1] == bottom{
        for prop in pj{
            if clue[2] == prop{
                return 1
            }       
        }
        return 0
    }
    assert!(false, "Please give a correct answer.");
    return 2
}


// Algorithm Play. g0 is the generator used to build the public clue key of the player, pc is the public clue key, sc is the secret clue key of the player, (tj, pj) is the cell j, answer is the response given by the player for the cell j.
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, pc: Vec<RistrettoPoint>, sc: Scalar, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize)-> Proof{

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
	
    if answer == 1{ // answer is maybe.
        return prove_play_maybe(csprng, y0, y, g0, g, sc);  
    }
    if answer == 0{ // answer is no.
    	return prove_play_no(csprng, y0, y, g0, g, sc);
    }
    else{
	assert!(false,"Please give a correct answer.");
	return Proof::Error{err: false};
    }	
}

// Algorithm Verify.
pub fn verify(g0: RistrettoPoint, proof: Proof, pc: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize) -> bool{	
    
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
		
    match proof{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_0, z_1} =>{ 
    	    if answer == 1{
    		b = verify_play_maybe(y0, y, g0, g, r_0, r_1, c_1, z_0, z_1); 
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} =>{ 
    	    let mut h: Vec<RistrettoPoint> = Vec::new(); 
            let h0 = -y0;
            for yy in &y{
                h.push(-yy);
            }
    	    if answer == 0{
    		b = verify_play_no(y0, y, g0, g, h0, h, y_0_p, y_1_p, r_0, r_r, s_0 ,s_s, u_u, v_v);
    	    }
    	},
    	Proof::Error{err} =>{   	
   	    if answer != 0 || answer != 1{
   		assert!(false, "Please give a correct answer.");
   		b = err;
   	    }
    	},
    }
    return b  
}

// Prove Play "maybe": it generates the zero knowledge proof when the answer of the player is "maybe".
// y0 is the public key pk of the player, y is the vector of all "c2/tj" (or resp. "c2/p") s.t. Dec_sk((c1, c2)) = Tj (or resp. Dec_sk((c1, c2)) = P belongs to Pj), g0 is the generator used to generate the public key of the player, g is the vector of all "c1", x is the secret key sk. (we prove also that y0 = g0^sk).
fn prove_play_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0:  RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }
   
    // It find the index w s.t. y[w] = x * g[w].
    let mut k = 0;
    while k < y.len() && y[k] != x * g[k]{
        k += 1;
    }
    let mut w = k;
    if w == y.len(){
        w -= 1;
    }
   
    // Commit:
    let mut r = init_vec_ristretto(y.len()); // r is the vector of commit.  
    let rr = random_scalar(csprng); // It picks a random scalar.
    let rrr = random_scalar(csprng); // It picks another random scalar. 
    let r0 = rr * g0; 
    r[w] = rrr * g[w];

    // Simulation for all y[i] s.t. y[i] != x * g[i].
    let mut c = init_vec_scalar(y.len()); // c[i] is the challenge corresponds to (yi, gi).
    let mut z = init_vec_scalar(y.len()); // z[i] is the response corresponds to (yi, gi).
    
    let respsim = simul_maybe(csprng, (&y).to_vec(), (&g).to_vec(), (&r).to_vec(), (&c).to_vec(), (&z).to_vec(), w);   
    r = respsim.0; 
    c = respsim.1; 
    z = respsim.2;

    // Challenge:  
    let mut conc: Vec<RistrettoPoint> = Vec::new(); // It builds the vector for concatenation and hashing.    
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc); // cc is the sum of all c[i].
    let mut sum = convert_scalar([0u8; 32]);
    for chall in &c{
        sum = sum + chall;
    }
    c[w] = cc - sum;
    
    // Response:
    let z0 = rr + cc * x;
    z[w] = rrr + c[w] * x;

    return Proof::ProofMaybe{r_0: r0, r_1: r, c_1: c, z_0: z0, z_1: z};
}

// Simulator for the yi such that y[i] != x * g[i]. 
fn simul_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, mut r:  Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut z: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){
    
    for k in 0..y.len(){
        if k != w {
            c[k] = random_scalar(csprng);
            z[k] = random_scalar(csprng);
            r[k] = z[k] * g[k] - c[k] * y[k];   
        }
    }
    return(r, c, z)
}

// Verify the proof when the answer is "maybe".
fn verify_play_maybe(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, r0:  RistrettoPoint, r: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, z: Vec<Scalar>) -> bool{
	
    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
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
    
    // It verifies if the computed challenge is the sum of challenge and z[i] * g[i] == r[i] + c[i] * y[i].
    if cc == sum && z0 * g0 == r0 + cc * y0{
    	for i in 0..y.len(){
    	    if z[i] * g[i] != r[i] + c[i] * y[i]{
        	return false   
            }
        }
        return true;
    }
    else{
        return false      
    }    
}

// Prove Play "no": it generates the zero knowledge proof when the answer of the player is "no".
fn prove_play_no<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0:  RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }

    let bb = random_scalar(csprng);
    let aa = x * bb;
	
    // Commit 
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);    
    let mut r: Vec<RistrettoPoint> = Vec::new(); 
    let r0 = rr * g0;
    for gg in &g{
        r.push(rr * gg);
    }
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-yy);
    }
    let mut s: Vec<RistrettoPoint> = Vec::new(); 
    let s0 = ss * h0;
    for hh in &h{
        s.push(ss * hh);
    }
    let y0_p = aa * g0 + bb * h0;	
    let mut y_p: Vec<RistrettoPoint> = Vec::new();
    for k in 0..g.len(){
	y_p.push(aa * g[k] + bb * h[k]);
    }
    
    // Challenge:
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
    
    // Response:
    let uu = rr + cc * aa;
    let vv = ss + cc * bb;
    
    return Proof::ProofNo{y_0_p: y0_p, y_1_p: y_p, r_0: r0, r_r: r, s_0: s0, s_s: s, u_u: uu, v_v: vv}; 	   
}   
  
fn verify_play_no(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, h0:  RistrettoPoint, h: Vec<RistrettoPoint>, y0_p: RistrettoPoint, y_p: Vec<RistrettoPoint>, r0: RistrettoPoint, r:  Vec<RistrettoPoint>, s0: RistrettoPoint, s: Vec<RistrettoPoint>, uu: Scalar, vv: Scalar) -> bool{

    // It computes the challenge with the given values.
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
    
    if y0_p == RistrettoPoint::identity() && uu * g0 + vv * h0 == r0 + s0 + cc * y0_p{ // y0_p must be equal to identity.
    	for k in 0..y_p.len(){
            if y_p[k] == RistrettoPoint::identity(){ // for all k, y_p[k] must be not equal to identity.
                return false;
            }
            else{
                if uu * g[k] + vv * h[k] != r[k] + s[k] + cc * y_p[k]{
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


// It measures over iter iterations the computation time of the algorithms ProveGame and VerifyGame and the size of the proof generated.
pub fn measurementsvcc<T: CryptoRng + RngCore>(csprng: &mut T, genmaster: RistrettoPoint, genplayers: Vec<RistrettoPoint>, cluesforms: Vec<usize>, n: usize, iter: u32){
    
    let mut sumprovegame = Duration::ZERO;
    let mut sumverifygame = Duration::ZERO;
    let mut proofgamesize = 0;
    
    println!("Average running time of the algorithms ProveGame and VerifyGame, and average of proof size calculated over {:?} iterations.\n", iter);   
    println!("Execution in progress...\n(The process may take a long time.)\n");
    
    for _j in 0..iter {
    
        let maps = typesandproperties(csprng); // Random generation of five types and fourteen properties in a RistrettoPoint. 
        let t = maps.0; // Vector of five types.
        let p = maps.1; // Vector of fourteen properties.
        let bottom = maps.2;
    
    	//It generates a random map
    	let map = buildrandommap((&t).to_vec(),(&p).to_vec(),n);
    	let maptypes = map.0;
    	let mapprop = map.1;
    
    	//It generates an random cryptid habitat
    	let between = Uniform::from(0..n);
    	let mut rngn = rand::thread_rng();
    	let j = between.sample(&mut rngn);
    
    	//It generates random clues according to the cryptid habitat.
    	let playerclues = buildplayerclues((&t).to_vec(), (&p).to_vec(), bottom, maptypes[j], (&mapprop[j]).to_vec(),	(&cluesforms).to_vec());
    	let keyc = genplayerclues(csprng, (&genplayers).to_vec(), (&playerclues).to_vec());
    	let pcplayers = keyc.0;
    	let scplayers = keyc.1;
    
    	let startprovegame = Instant::now();
    	let proof = provegame(csprng,(&t).to_vec(), (&p).to_vec(), bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), j, genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), (&scplayers).to_vec());
    	let provegametime = startprovegame.elapsed();
    	sumprovegame += provegametime;
    
        let pg = proof.0;
        let proof0 = proof.1;
        let proof1 = proof.2;
        let proof2 = proof.3;
        let proof3 = proof.4;
        
        // It write the proof of the correct game in the file "proofgame.txt".
        let _ = writeproofgame((&pg).to_vec(), &proof0, &proof1, &proof2, &proof3);
    	let proofdata = fs::metadata("proofgame.txt");
    	proofgamesize += proofdata.expect("REASON").len();
    
        let startverifygame = Instant::now();
        let b = verifygame((&t).to_vec(), (&p).to_vec(), bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), pg, proof0, proof1, proof2, proof3);
        let verifygametime = startverifygame.elapsed();
        println!("VerifyGame is {:?}.", b);
        assert!(b == (true, true, true, true), "VerifyGame is false");
        sumverifygame += verifygametime;
    }
    let averageprovegametime = sumprovegame/iter;
    let averageverifygametime = sumverifygame/iter;
    let averageproofgamesize = proofgamesize/u64::from(iter);
    println!("\nProveGame: {:?}\nVerifyGame: {:?}\nSize of proof of correct game: {:?}\n", averageprovegametime, averageverifygametime, averageproofgamesize);
}

// Algorithms for the scheme VCC:
// Algorithm ProveGame.
pub fn provegame<T: CryptoRng + RngCore>(csprng: &mut T, t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, maptypes: Vec<RistrettoPoint>, mapprop: Vec<Vec<RistrettoPoint>>, j: usize, genmaster: RistrettoPoint, genplayers: Vec<RistrettoPoint>, pcplayers: Vec<Vec<RistrettoPoint>>, scplayers: Vec<Scalar>) -> (Vec<RistrettoPoint>, Proofgame0, Proofgame1, Vec<Proofgame2>, Vec<Proofgame3>){
    
    let n = maptypes.len(); // n is the number of cells.
    let keyc = buildmaster(csprng, genmaster, maptypes[j], (&mapprop[j]).to_vec(), (&p).to_vec());
    let pg = keyc.0;
    let sc = keyc.1;
     
    // Proof rho_0:
    // Sum of El.
    let mut sumc1 = RistrettoPoint::identity(); 
    let mut sumc2 = RistrettoPoint::identity(); 
    let mut k = 3; // pg[0] = pk, pg[1] = c10, pg[2] = c20.
    while k < 2*(p.len())+3{
        sumc1 += pg[k]; 
        sumc2 += pg[k+1]; 
        k += 2;
    }
    // Sum of pi for all cell_i.
    let mut sumi: Vec<RistrettoPoint> = Vec::new();
    for i in 0..n{
       let mut sum = RistrettoPoint::identity();
       for l in 0..mapprop[i].len(){
	   sum += mapprop[i][l]; 
       }
       sumi.push(sum); // sumi = H(cell_i).
    }
    let ghl = vec![sumc1; n];
    let mut yhl = init_vec_ristretto(n);
    for i in 0..n{
        yhl[i] = sumc2 - sumi[i];
    }
    let ge0 = vec![pg[1];n];
    let mut ye0 = init_vec_ristretto(n);
    for i in 0..n{
    	ye0[i] = pg[2] - maptypes[i];
    }
    let proof0 = prove_game0(csprng, pg[0], yhl, ye0, genmaster, ghl, ge0, sc);
    
    // Proof rho_1:
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
    let proof1 = prove_game1(csprng, pg[0], c2pl, c2l, genmaster, (&c1l).to_vec(), (&c1l).to_vec(), sc);
    
    let mut proof2: Vec<Proofgame2> = Vec::new();
    let mut proof3: Vec<Proofgame3> = Vec::new();
    for player in 0..genplayers.len(){
    
        // Proof rho_2:	
        let mut y: Vec<RistrettoPoint> = Vec::new();
        let mut g: Vec<RistrettoPoint> = Vec::new();
        let mut h: Vec<RistrettoPoint> = Vec::new();	
        y.push(pg[2] - pcplayers[player][2]);
        y.push(pg[2] - pcplayers[player][4]);	
        g.push(pg[1]);
        g.push(pg[1]);	
        h.push(-pcplayers[player][1]);
        h.push(-pcplayers[player][3]); 		
        let mut l = 3;
        while l < pg.len(){
       	    y.push(pg[l+1] - pcplayers[player][6]);
    	    h.push(-pcplayers[player][5]);
   	    g.push(pg[l]); 	    
    	    l += 2;
        }
        let proof2player = prove_game2(csprng, pg[0], pcplayers[player][0], y, genmaster, genplayers[player], g, h, sc, scplayers[player]);
        proof2.push(proof2player);  
        
        // Proof rho_3:     
        let y1 = pcplayers[player][6] - bottom;
        let g1 = pcplayers[player][5];
        let y2 = pcplayers[player][2] - pcplayers[player][4]; // Note that y2 = y5.
        let g2 = pcplayers[player][1] - pcplayers[player][3]; // Note that g2 = g5.  	
        let mut y3: Vec<RistrettoPoint> = Vec::new();
        let mut g3: Vec<RistrettoPoint> = Vec::new();
        let mut y4: Vec<RistrettoPoint> = Vec::new();
        let mut g4: Vec<RistrettoPoint> = Vec::new();           
        for i in 0..t.len(){
            y3.push(pcplayers[player][2] - t[i]);
            y4.push(pcplayers[player][4] - t[i]); 
            g3.push(pcplayers[player][1]);
            g4.push(pcplayers[player][3]);
        }     
        let y6 = pcplayers[player][4] - bottom;
        let g6 = pcplayers[player][3];    
        let mut y7: Vec<RistrettoPoint> = Vec::new();
        let mut g7: Vec<RistrettoPoint> = Vec::new();   
        for k in 0..p.len(){
            y7.push(pcplayers[player][6] - p[k]);
            g7.push(pcplayers[player][5]);
        }     
        let proof3player = prove_game3(csprng, pcplayers[player][0], y1, y2, y3, y4, y2, y6, y7, genplayers[player], g1, g2, g3, g4, g2, g6, g7, scplayers[player]);
        proof3.push(proof3player);       
    }
    return (pg,proof0,proof1,proof2,proof3);
}  

// Algorithm VerifyGame.
pub fn verifygame(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, maptypes: Vec<RistrettoPoint>, mapprop: Vec<Vec<RistrettoPoint>>, genmaster: RistrettoPoint, genplayers: Vec<RistrettoPoint>, pcplayers: Vec<Vec<RistrettoPoint>>, pg: Vec<RistrettoPoint>, proof0: Proofgame0, proof1: Proofgame1, proof2: Vec<Proofgame2>, proof3: Vec<Proofgame3>) -> (bool, bool, bool, bool){
   
    let n = maptypes.len();  
    let mut b0 = true;
    let mut b1 = true;
    let mut b2 = true;
    let mut b3 = true;
   
    // Proof rho_0:
    let mut sumc1 = RistrettoPoint::identity(); 
    let mut sumc2 = RistrettoPoint::identity(); 
    let mut k = 3; // pg[0] = pk, pg[1] = c1[0] and pg[2] = c2[0], ...
    while k < 2*(p.len())+3{
        sumc1 += pg[k]; 
        sumc2 += pg[k+1]; 
        k += 2;
    }
    // Sum of all properties of a cell_i.
    let mut sumi: Vec<RistrettoPoint> = Vec::new();
    for i in 0..n{
       let mut sum = RistrettoPoint::identity();
       for l in 0..mapprop[i].len(){
	   sum += mapprop[i][l]; 
       }
       sumi.push(sum); // sumi = H(cell_i).
    }
    let ghl = vec![sumc1; n];
    let mut yhl = init_vec_ristretto(n);
    for i in 0..n{
        yhl[i] = sumc2 - sumi[i];
    }
    let ge0 = vec![pg[1]; n];
    let mut ye0 = init_vec_ristretto(n);
    for i in 0..n{
    	ye0[i] = pg[2] - maptypes[i];
    }	
    match proof0{
        Proofgame0{r_0, r_1, r_2, c_c, z_0, z_z} =>{ 
            if verify_game0(pg[0], yhl, ye0, genmaster, ghl, ge0, r_0, r_1, r_2, c_c, z_0, z_z) == false{
                b0 = false;
            }
        }
    } 
    
    // Proof rho_1:
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
        Proofgame1{r_0, r_1, r_2, c_1, c_2, z_0, z_1, z_2} =>{ 
            if verify_game1(pg[0], (&c2pl).to_vec(), (&c2l).to_vec(), genmaster, (&c1l).to_vec(), (&c1l).to_vec(), r_0, r_1, r_2, c_1, c_2, z_0, z_1, z_2) == false{
                b1 = false;
            }
        }
    }   
    
    for player in 0..genplayers.len(){
    
        // Proof rho_2: 	
        let mut y: Vec<RistrettoPoint> = Vec::new();
        let mut g: Vec<RistrettoPoint> = Vec::new();
        let mut h: Vec<RistrettoPoint> = Vec::new();
    	y.push(pg[2] - pcplayers[player][2]);
    	y.push(pg[2] - pcplayers[player][4]);
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
            Proofgame2{r_0, r_a, r_1, r_2, c_c, z_0, z_a, z_1, z_2} =>{
                if verify_game2(pg[0], pcplayers[player][0], y, genmaster, genplayers[player], g, h, *r_0, *r_a,(&r_1).to_vec(), (&r_2).to_vec(), (&c_c).to_vec(), *z_0, *z_a, (&z_1).to_vec(), (&z_2).to_vec()) == false{
                    b2 = false;
                }
            }
        }
         
        // Proof rho_3:   
        let y0 = pcplayers[player][0];
        let g0 = genplayers[player];
        let y1 = pcplayers[player][6] - bottom;
        let g1 = pcplayers[player][5];
        let y2 = pcplayers[player][2] - pcplayers[player][4]; // y2 = y5.
        let g2 = pcplayers[player][1] - pcplayers[player][3]; // g2 = g5.
        let mut y3: Vec<RistrettoPoint> = Vec::new();
        let mut g3: Vec<RistrettoPoint> = Vec::new();
        let mut y4: Vec<RistrettoPoint> = Vec::new();
        let mut g4: Vec<RistrettoPoint> = Vec::new();       
        for i in 0..t.len(){
            y3.push(pcplayers[player][2] - t[i]);
            y4.push(pcplayers[player][4] - t[i]); 
            g3.push(pcplayers[player][1]);
            g4.push(pcplayers[player][3]);
        }
        let y6 = pcplayers[player][4] - bottom;
        let g6 = pcplayers[player][3];
        let mut y7: Vec<RistrettoPoint> = Vec::new();
        let mut g7: Vec<RistrettoPoint> = Vec::new();
        for k in 0..p.len(){
            y7.push(pcplayers[player][6] - p[k]);
            g7.push(pcplayers[player][5]);
        }    
        let proof3player = &proof3[player];
        match proof3player{
            Proofgame3{y_1_p, y_2_p, r_0, r_1, s_1, r_2, s_2, r_3, r_4, r_5, r_6, r_7, c_00, c_01, c_3, c_4, c_7, z_0, u_u, v_v, z_3, z_4, z_56, z_7} =>{
                if verify_game3(y0, y1, y2, y3, y4, y2, y6, y7, g0, g1, g2, g3, g4, g2, g6, g7, *y_1_p, *y_2_p, *r_0, *r_1, *s_1, *r_2, *s_2, (&r_3).to_vec(), (&r_4).to_vec(), *r_5, *r_6, (&r_7).to_vec(), *c_00, *c_01, (&c_3).to_vec(),(&c_4).to_vec(), (&c_7).to_vec(), *z_0, *u_u, *v_v, (&z_3).to_vec(), (&z_4).to_vec(), *z_56, (&z_7).to_vec()) == false{
                    b3 = false;
                }
            }
        }          
    }
    return (b0, b1, b2, b3);  
}

// It builds the proof rho_0.
pub fn prove_game0<T:CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>, x: Scalar) -> Proofgame0 {

    let mut k = 0;
    while k < y1.len() && (y1[k] != x * g1[k] || y2[k] != x * g2[k]){
        k = k + 1;
    }
    let mut w = k;
    if w == y1.len(){
        w = w - 1;
    }
    
    // Commit:
    let mut r1 = init_vec_ristretto(y1.len());
    let mut r2 = init_vec_ristretto(y2.len());
    let rr = random_scalar(csprng);
    r2[w] = rr * g2[w]; // w = index j.
    r1[w] = rr * g1[w]; // w = index j.
    let rr0 = random_scalar(csprng);
    let r0 = rr0 * g0;
    
    // Simulation:
    let mut c = init_vec_scalar(y1.len());  
    let mut z = init_vec_scalar(y1.len());
    let respsim = simul_game0(csprng, (&y1).to_vec(), (&g1).to_vec(), (&y2).to_vec(), (&g2).to_vec(), (&r1).to_vec(), (&r2).to_vec(), (&c).to_vec(), (&z).to_vec(), w);
    r1 = respsim.0;
    r2 = respsim.1;
    c = respsim.2;
    z = respsim.3;
    
    // Challenge:
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
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
        sum = sum + chall;
    }
    c[w] = cc - sum;
    
    // Response:
    z[w] = rr + c[w] * x;
    let z0 = rr0 + cc * x;

    return Proofgame0{r_0: r0, r_1: r1, r_2: r2, c_c: c, z_0: z0, z_z: z}; 
} 

pub fn simul_game0<T: CryptoRng + RngCore>(csprng: &mut T, y1: Vec<RistrettoPoint>, g1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>, mut r1: Vec<RistrettoPoint>, mut r2: Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut z: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){  
 
    for k in 0..y1.len(){
        if k != w {
            c[k] = random_scalar(csprng);
            z[k] = random_scalar(csprng);
            r1[k] = z[k] * g1[k] - c[k] * y1[k];   
            r2[k] = z[k] * g2[k] - c[k] * y2[k]; 
        }
    }
    return(r1, r2, c, z)
}

// Verify the proof rho_0.	
pub fn verify_game0(y0: RistrettoPoint, y1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>, r0: RistrettoPoint, r1: Vec<RistrettoPoint>, r2: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, z: Vec<Scalar>) -> bool{

    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
    conc.extend((&r1).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());   
    let cc = hash_vec(conc); 
    let mut sum = convert_scalar([0u8; 32]);
    for chall in &c{
        sum += chall;
    }
    
    if cc == sum && z0 * g0 == r0 + cc * y0{
    	for l in 0..y1.len(){
    	    if z[l] * g1[l] != r1[l] + c[l] * y1[l] || z[l] * g2[l] != r2[l] + c[l] * y2[l]{
    	        return false;
    	    }
        }
        return true;
    }
    else{
        return false;
    }
}
  
pub fn prove_game1<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>, x: Scalar) -> Proofgame1{

    // Commit:  
    let mut r1 = init_vec_ristretto(y1.len());
    let mut r2 = init_vec_ristretto(y2.len());
    let mut c1 = init_vec_scalar(y1.len());
    let mut c2 = init_vec_scalar(y2.len());
    let mut z1 = init_vec_scalar(y1.len());
    let mut z2 = init_vec_scalar(y2.len());
    let mut rrr: Vec<Scalar> = Vec::new();
    let rr = random_scalar(csprng);
    let r0 = rr * g0;
    for l in 0..14{
    	if y1[l] == x * g1[l]{ // It send the others to the simulator.
    	    let rr1 = random_scalar(csprng);
    	    r1[l] = rr1 * g1[l]; 
    	    rrr.push(rr1);
    	    let respsim = simul_game1(csprng,y2[l],g2[l]);
    	    r2[l] = respsim.0;
    	    c2[l] = respsim.1;
    	    z2[l] = respsim.2;       
    	}
    	else{ // y2[l] == x * g2[l] or return a false proof.
    	    let rr2 = random_scalar(csprng);
    	    r2[l] = rr2 * g2[l]; 
    	    rrr.push(rr2);
    	    let respsim = simul_game1(csprng,y1[l],g1[l]);
    	    r1[l] = respsim.0; 
    	    c1[l] = respsim.1;
    	    z1[l] = respsim.2; 
    	}
    }
    
    // Challenge:
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r0);
    conc.extend((&r1).to_vec());
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
    	    // Response:
	    z1[l] = rrr[l] + c1[l] * x;         
    	}
    	else{ 
    	    c2[l] = cc - c1[l]; 
    	    // Response:
	    z2[l] = rrr[l] + c2[l] * x; 
    	}
    }
    let z0 = rr + cc * x;
   
    return Proofgame1{r_0: r0, r_1: r1, r_2: r2, c_1: c1, c_2: c2, z_0 : z0, z_1: z1, z_2: z2}
}
    
pub fn simul_game1<T: CryptoRng + RngCore>(csprng: &mut T, y: RistrettoPoint, g: RistrettoPoint) -> (RistrettoPoint, Scalar, Scalar){

    let c = random_scalar(csprng);
    let z = random_scalar(csprng);
    let r = z * g - c * y;
    return(r, c, z)
}

pub fn verify_game1(y0: RistrettoPoint, y1: Vec<RistrettoPoint>, y2: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: Vec<RistrettoPoint>, g2: Vec<RistrettoPoint>, r0: RistrettoPoint,  r1: Vec<RistrettoPoint>, r2: Vec<RistrettoPoint>, c1: Vec<Scalar>, c2: Vec<Scalar>, z0: Scalar, z1: Vec<Scalar>, z2: Vec<Scalar>) -> bool{
    
    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r0);
    conc.extend((&r1).to_vec());
    conc.extend((&r2).to_vec());
    conc.push(y0);
    conc.extend((&y1).to_vec());
    conc.extend((&y2).to_vec());
    conc.push(g0);
    conc.extend((&g1).to_vec());
    conc.extend((&g2).to_vec());
    let cc = hash_vec(conc);
     
    for l in 0..y1.len(){
    	if cc != c1[l] + c2[l] || z1[l] * g1[l] != r1[l] + c1[l] * y1[l] || z2[l] * g2[l] != r2[l] + c2[l] * y2[l] || z0 * g0 != r0 + cc * y0{
    	    return false  
    	}
    	return true
    }
    return false
}

pub fn prove_game2<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, ya: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, ga:RistrettoPoint, g: Vec<RistrettoPoint>, h: Vec<RistrettoPoint>, x: Scalar, xa: Scalar) -> Proofgame2{
    
    let mut k = 0;
    while k < y.len() && (y[k] != x * g[k] + xa * h[k]){ // y[k] = x * g[k] + xa * h[k].
        k = k + 1;
    }
    let mut w = k; 
    if w == y.len(){
        w = w - 1;
    }  
    
    // Commit: 
    let rrr = random_scalar(csprng);
    let r0 = rrr * g0;
    let sss = random_scalar(csprng);
    let ra = sss * ga;
    let mut r = init_vec_ristretto(y.len());
    let mut s = init_vec_ristretto(y.len());
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);
    r[w] = rr * g[w];
    s[w] = ss * h[w];
    
    let mut c = init_vec_scalar(y.len());
    let mut u = init_vec_scalar(y.len());
    let mut v = init_vec_scalar(y.len());
        
    // Simulator:
    let respsim = simul_game2(csprng, (&y).to_vec(), (&g).to_vec(), (&h).to_vec(), (&r).to_vec(), (&s).to_vec(),(&c).to_vec(), (&u).to_vec(), (&v).to_vec(), w);
    
    r = respsim.0;
    s = respsim.1;
    c = respsim.2;
    u = respsim.3;
    v = respsim.4;
    
    // Challenge:
    let mut sum = convert_scalar([0u8; 32]);
    for chall in &c{
        sum += chall;
    }
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r0);
    conc.push(ra);
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
    
    // Response:
    let z0 = rrr + cc * x;
    let za = sss + cc * xa;
    
    return Proofgame2{r_0: r0, r_a: ra, r_1: r, r_2: s, c_c: c, z_0: z0, z_a: za, z_1: u, z_2: v};
}
 
pub fn simul_game2<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, h: Vec<RistrettoPoint>, mut r: Vec<RistrettoPoint>, mut s: Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut u: Vec<Scalar>, mut v: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>){

    for i in 0..y.len(){
    	if i != w{
    	    c[i] = random_scalar(csprng);
    	    u[i] = random_scalar(csprng);
    	    v[i] = random_scalar(csprng);
    	    r[i] = random_point(csprng);
    	    s[i] = u[i] * g[i] + v[i] * h[i] - (r[i] + c[i] * y[i]);
    	}
    }
    return (r, s, c, u, v)   
}
      
pub fn verify_game2(y0: RistrettoPoint, ya: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, ga:RistrettoPoint, g: Vec<RistrettoPoint>, h: Vec<RistrettoPoint>, r0: RistrettoPoint, ra: RistrettoPoint, r: Vec<RistrettoPoint>, s: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, za: Scalar, u: Vec<Scalar>, v: Vec<Scalar>) -> bool{

    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r0);
    conc.push(ra);
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

    let mut sum = convert_scalar([0u8; 32]);
    for chall in &c{
        sum += chall;
    }   
    if sum == cc && r0 == z0 * g0 - cc * y0 && ra == za * ga - cc * ya {
    	for i in 0..y.len(){
    	    if r[i] + s[i] != u[i] * g[i] + v[i] * h[i] - c[i] * y[i] {
    	    	return false;
    	    }
    	}
    	return true;
    }
    else{
        return false; 	
    }
}

pub fn prove_game3<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y1: RistrettoPoint, y2: RistrettoPoint, y3: Vec<RistrettoPoint>, y4: Vec<RistrettoPoint>, y5: RistrettoPoint, y6: RistrettoPoint, y7: Vec<RistrettoPoint>, g0: RistrettoPoint, g1: RistrettoPoint, g2: RistrettoPoint, g3: Vec<RistrettoPoint>, g4: Vec<RistrettoPoint>, g5: RistrettoPoint, g6: RistrettoPoint, g7: Vec<RistrettoPoint>, x: Scalar) -> Proofgame3{

    // It determines which part of the proof is true.
    let mut truepart1 = 0;
    let mut truepart3 = 0;
    let mut truepart4 = 0;
    if y0 == x * g0 && y1 == x * g1 && y2 != x * g2{
        truepart1 = 1;
        for l in 0..y3.len(){
            if y3[l] == x * g3[l]{
    	        truepart3 = 1; 
    	    } 
    	    if y4[l] == x * g4[l]{
    	        truepart4 = 1;
    	    }   	
        }
    } 
    let truepart = truepart1 * truepart3 * truepart4;
    if truepart == 1 { //The first part is true and the other is send to the simulator.

        // Commit:
        let bb = random_scalar(csprng);
        let aa = x * bb;

        let h1 = -y1;
        let h2 = -y2;
    
        let y1_p = aa * g1 + bb * h1;
        let y2_p = aa * g2 + bb * h2;
    
        let rr = random_scalar(csprng);
        let ss = random_scalar(csprng);
        let rrr = random_scalar(csprng);
    
        // First part of proof:
        let r0 = rrr * g0;
        let r1 = rr * g1;
        let r2 = rr * g2;
        let s1 = ss * h1;
        let s2 = ss * h2;  
        
        // Simulator for prove "or".
        let respsim3 = prove_or(csprng, (&y3).to_vec(), (&g3).to_vec(), x);
        let mut r3 = respsim3.0;
        let mut c3 = respsim3.1; // without the challenge for c3[w3] which depend on C00.
        let mut z3 = respsim3.2;
        let w3 = respsim3.3;
        let rr3 = random_scalar(csprng);
        r3[w3] = rr3 * g3[w3];
        
        let respsim4 = prove_or(csprng, (&y4).to_vec(), (&g4).to_vec(), x);       
        let mut r4 = respsim4.0;
        let mut c4 = respsim4.1; // without the challenge for c4[w4] which depend on C00.
        let mut z4 = respsim4.2;
        let w4 = respsim4.3;
        let rr4 = random_scalar(csprng);
        r4[w4] = rr4 * g4[w4];
           
        // The second part of proof is simulated.
        let c01 = random_scalar(csprng);
        let z56 = random_scalar(csprng);
        let r5 = z56 * g5 - c01 * y5;
        let r6 = z56 * g6 - c01 * y6;
        let mut c7: Vec<Scalar> = Vec::new();
        let mut z7: Vec<Scalar> = Vec::new();
        let mut r7: Vec<RistrettoPoint> = Vec::new();
        let mut sum7 = convert_scalar([0u8; 32]);
        for l in 0..y7.len()-1{
            c7.push(random_scalar(csprng));
            z7.push(random_scalar(csprng));
            sum7 += c7[l];
            r7.push(z7[l] * g7[l] - c7[l] * y7[l]);      
        }
        c7.push(c01 - sum7);
        z7.push(random_scalar(csprng));
        r7.push(z7[y7.len()-1] * g7[y7.len()-1] - c7[y7.len()-1] * y7[y7.len()-1]); 
        
        // Challenge: 
        let mut conc: Vec<RistrettoPoint> = Vec::new();
        conc.push(r0);
        conc.push(r1);
        conc.push(r2);
        conc.push(s1);
        conc.push(s2);
        conc.extend((&r3).to_vec());
        conc.extend((&r4).to_vec());
        conc.push(r5);
        conc.push(r6);
        conc.extend((&r7).to_vec());
        conc.push(y0);
        conc.push(y1);
        conc.push(y2);
        conc.extend((&y3).to_vec());
        conc.extend((&y4).to_vec());
        conc.push(y5);
        conc.push(y6);
        conc.extend((&y7).to_vec());
        conc.push(y1_p);
        conc.push(y2_p);
        conc.push(g0);
        conc.push(g1);
        conc.push(g2);
        conc.push(h1);
        conc.push(h2);
        conc.extend((&g3).to_vec());
        conc.extend((&g4).to_vec());
        conc.push(g5);
        conc.push(g6);
        conc.extend((&g7).to_vec());
        let cc = hash_vec(conc);
        let c00 = cc - c01;
        let mut sum3 = convert_scalar([0u8; 32]);
        for chall in &c3{
            sum3 += chall;
        }  
        c3[w3] = c00 - sum3;
        let mut sum4 = convert_scalar([0u8; 32]);
        for chall in &c4{
            sum4 += chall;
        } 
        c4[w4] = c00 - sum4;   
        
        // Response:
        let z0 = rrr + cc*x;
        z3[w3] = rr3 + c3[w3] * x;
        z4[w4] = rr4 + c4[w4] * x;
        let uu = rr + c00 * aa; 
        let vv = ss + c00 * bb;
            
        return Proofgame3{y_1_p: y1_p, y_2_p: y2_p, r_0: r0, r_1: r1, s_1: s1, r_2: r2, s_2: s2, r_3: r3, r_4: r4, r_5: r5, r_6: r6, r_7: r7, c_00: c00, c_01: c01, c_3: c3, c_4: c4, c_7: c7, z_0: z0, u_u: uu, v_v: vv, z_3: z3, z_4: z4, z_56: z56, z_7: z7};
        
    }
    else{ // The second part of proof is true or it builds a false proof.
        
        // Commit:
        let rrr = random_scalar(csprng);
        let r0 = rrr * g0;
        
        // It simulates the first part.
        let y1_p = RistrettoPoint::identity();
        let mut y2_p = random_point(csprng);
        while y2_p == RistrettoPoint::identity(){
            y2_p = random_point(csprng);
        }  
        let h1 = -y1;
        let h2 = -y2;
        let s1 = random_point(csprng);
        let s2 = random_point(csprng);  
        let uu = random_scalar(csprng);
        let vv = random_scalar(csprng);
        let c00 = random_scalar(csprng);
        let r1 = uu * g1 + vv * h1 - s1 - c00 * y1_p;
        let r2 = uu * g2 + vv * h2 - s2 - c00 * y2_p;
        let mut c3: Vec<Scalar> = Vec::new();
        let mut z3: Vec<Scalar> = Vec::new();
        let mut r3: Vec<RistrettoPoint> = Vec::new();
        let mut sum3 = convert_scalar([0u8; 32]);
        for l in 0..y3.len()-1{
            c3.push(random_scalar(csprng));
            z3.push(random_scalar(csprng));
            sum3 += c3[l];
            r3.push(z3[l] * g3[l] - c3[l] * y3[l]);      
        }
        c3.push(c00 - sum3);
        z3.push(random_scalar(csprng));
        r3.push(z3[y3.len()-1] * g3[y3.len()-1] - c3[y3.len()-1] * y3[y3.len()-1]); 
        let mut c4: Vec<Scalar> = Vec::new();
        let mut z4: Vec<Scalar> = Vec::new();
        let mut r4: Vec<RistrettoPoint> = Vec::new();  
        let mut sum4 = convert_scalar([0u8; 32]);       
        for l in 0..y4.len()-1{
            c4.push(random_scalar(csprng));
            z4.push(random_scalar(csprng));
            sum4 += c4[l];
            r4.push(z4[l] * g4[l] - c4[l] * y4[l]);      
        }        
        c4.push(c00 - sum4);
        z4.push(random_scalar(csprng));
        r4.push(z4[y4.len()-1] * g4[y4.len()-1] - c4[y4.len()-1] * y4[y4.len()-1]); 
        
        // The second part of proof is true.
        let rr = random_scalar(csprng);
        let r5 = rr * g5;
        let r6 = rr * g6;
        let respsim7 = prove_or(csprng, (&y7).to_vec(), (&g7).to_vec(), x);       
        let mut r7 = respsim7.0;
        let mut c7 = respsim7.1;
        let mut z7 = respsim7.2;
        let w7 = respsim7.3;
        let rr7 = random_scalar(csprng);
        r7[w7] = rr7 * g7[w7];
        
        // Challenge:
        let mut conc: Vec<RistrettoPoint> = Vec::new();
        conc.push(r0);
        conc.push(r1);
        conc.push(r2);
        conc.push(s1);
        conc.push(s2);
        conc.extend((&r3).to_vec());
        conc.extend((&r4).to_vec());
        conc.push(r5);
        conc.push(r6);
        conc.extend((&r7).to_vec());
        conc.push(y0);
        conc.push(y1);
        conc.push(y2);
        conc.extend((&y3).to_vec());
        conc.extend((&y4).to_vec());
        conc.push(y5);
        conc.push(y6);
        conc.extend((&y7).to_vec());
        conc.push(y1_p);
        conc.push(y2_p);
        conc.push(g0);
        conc.push(g1);
        conc.push(g2);
        conc.push(h1);
        conc.push(h2);
        conc.extend((&g3).to_vec());
        conc.extend((&g4).to_vec());
        conc.push(g5);
        conc.push(g6);
        conc.extend((&g7).to_vec());
        let cc = hash_vec(conc);  
        let c01 = cc - c00;    
        let mut sum7 = convert_scalar([0u8; 32]);
        for chall in &c7{
            sum7 += chall;
        }  
        c7[w7] = c01 - sum7;
       
        // Response:
        let z56 = rr + c01 * x;
        z7[w7] = rr7 + c7[w7] * x;
        let z0 = rrr + cc * x;
        
        return Proofgame3{y_1_p: y1_p, y_2_p: y2_p, r_0: r0, r_1: r1, s_1: s1, r_2: r2, s_2: s2, r_3: r3, r_4: r4, r_5: r5, r_6: r6, r_7: r7, c_00: c00, c_01: c01, c_3: c3, c_4: c4, c_7: c7, z_0: z0, u_u: uu, v_v: vv, z_3: z3, z_4: z4, z_56: z56, z_7: z7};
    }
}
           
pub fn verify_game3(y0: RistrettoPoint, y1: RistrettoPoint, y2: RistrettoPoint, y3: Vec<RistrettoPoint>, y4: Vec<RistrettoPoint>, y5: RistrettoPoint, y6: RistrettoPoint, y7:Vec<RistrettoPoint>, g0: RistrettoPoint, g1: RistrettoPoint, g2: RistrettoPoint, g3: Vec<RistrettoPoint>, g4: Vec<RistrettoPoint>, g5: RistrettoPoint, g6: RistrettoPoint, g7: Vec<RistrettoPoint>, y1_p: RistrettoPoint, y2_p: RistrettoPoint, r0: RistrettoPoint, r1: RistrettoPoint, s1: RistrettoPoint, r2: RistrettoPoint, s2: RistrettoPoint, r3: Vec<RistrettoPoint>, r4: Vec<RistrettoPoint>, r5: RistrettoPoint, r6: RistrettoPoint, r7: Vec<RistrettoPoint>, c00: Scalar, c01: Scalar, c3: Vec<Scalar>, c4: Vec<Scalar>, c7: Vec<Scalar>, z0: Scalar, uu: Scalar, vv: Scalar, z3: Vec<Scalar>, z4: Vec<Scalar>, z56: Scalar, z7: Vec<Scalar>) -> bool{
  
        
    // It computes the challenge with the given values.
    let h1 = -y1;
    let h2 = -y2;
    let mut conc: Vec<RistrettoPoint> = Vec::new();
    conc.push(r0);
    conc.push(r1);
    conc.push(r2);
    conc.push(s1);
    conc.push(s2);
    conc.extend((&r3).to_vec());
    conc.extend((&r4).to_vec());
    conc.push(r5);
    conc.push(r6);
    conc.extend((&r7).to_vec());
    conc.push(y0);
    conc.push(y1);
    conc.push(y2);
    conc.extend((&y3).to_vec());
    conc.extend((&y4).to_vec());
    conc.push(y5);
    conc.push(y6);
    conc.extend((&y7).to_vec());
    conc.push(y1_p);
    conc.push(y2_p);
    conc.push(g0);
    conc.push(g1);
    conc.push(g2);
    conc.push(h1);
    conc.push(h2);
    conc.extend((&g3).to_vec());
    conc.extend((&g4).to_vec());
    conc.push(g5);
    conc.push(g6);
    conc.extend((&g7).to_vec());
    let cc = hash_vec(conc);
        
    let mut sum3 = convert_scalar([0u8; 32]);
    for chall in &c3{
        sum3 += chall;
    }      
    let mut sum4 = convert_scalar([0u8; 32]);
    for chall in &c4{
        sum4 += chall;
    }      
    let mut sum7 = convert_scalar([0u8; 32]);
    for chall in &c7{
        sum7 += chall;
    }               
    if cc != c00 + c01 || r0 != z0 * g0 - cc * y0 || c00 != sum3 && c00 != sum4 || c01 != sum7 || y1_p != RistrettoPoint::identity() || y2_p == RistrettoPoint::identity(){
        return false
    }   
    if r1 + s1 != uu * g1 + vv * h1 - c00 * y1_p || r2 + s2 != uu * g2 + vv * h2 - c00 * y2_p{
        return false;      
    }
    for l in 0..y3.len(){
 	if r3[l] != z3[l] * g3[l] - c3[l] * y3[l]{
 	    return false;
 	}
    }
    for l in 0..y4.len(){
 	if r4[l] != z4[l] * g4[l] - c4[l] * y4[l]{
 	    return false;
 	}
    }	
    if r5 != z56 * g5 - c01 * y5 || r6 != z56 * g6 - c01 * y6{
 	return false;
    }	
    for l in 0..y7.len(){
 	if r7[l] != z7[l] * g7[l] - c7[l] * y7[l]{
 	    return false;
        }
    } 
    return true;
}

pub fn prove_or<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, x: Scalar) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>, usize) {
    
    let mut k = 0;
    while k < y.len() && (y[k] != x * g[k]){ // y[k] = x * g[k] + xa * h[k].
        k = k + 1;
    }
    let mut w = k; 
    if w == y.len(){
        w = w - 1;
    }
    
    let mut r = init_vec_ristretto(y.len());
    let mut z = init_vec_scalar(y.len());
    let mut c = init_vec_scalar(y.len());
    
    let respsim = simul_or(csprng, (&y).to_vec(), (&g).to_vec(), (&r).to_vec(), (&c).to_vec(), (&z).to_vec(), w);

    r = respsim.0;
    c = respsim.1;
    z = respsim.2;
    
    return (r, c, z, w);
}

pub fn simul_or<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, mut r: Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut z: Vec<Scalar>, w: usize) -> 
(Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){ 
    
    for i in 0..y.len(){
        if i != w{
            z[i] = random_scalar(csprng);
    	    c[i] = random_scalar(csprng);
    	    r[i] = z[i] * g[i] - c[i] * y[i];
        }
    }
    return(r, c, z);
}
